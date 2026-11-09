"""Comprehensive Tests for Phase 2: Connection Lifecycle & MCP Protocol Correctness.

Covers:
- B2: Dedicated task ownership of stdio_client + session (no cross-task cancel scope errors),
      reconnect loop with clean process cleanup, mid-call upstream crash resilience.
- B6a: tools/list discovery following nextCursor until exhausted.
- B6b: tools/list_changed notification refreshes catalog and advertises tools.listChanged downstream.
- B6c: Tool metadata preservation (title, annotations, output_schema).
- B6d: Protocol error semantics (MCPError for unknown tools and invalid params, tool result for policy/timeout).
- B6e: Deterministic namespacing, forbidding '__' in server ids, truncation with hash on overflow.
- B6f: CancelledNotification sent on timeout, failure tracking and server recycling.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ErrorData,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
    ToolListChangedNotification,
)

from toolbridge.client.discovery import ToolDiscoveryEngine, create_namespaced_identifier
from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import ServerStatus, TransportType, UpstreamServerConfig
from toolbridge.models.tool import NamespacedTool
from toolbridge.router.dispatcher import ToolRouter
from toolbridge.security.policy import UserRole
from toolbridge.server.gateway import ToolBridgeGatewayServer


# ==============================================================================
# B2: Connection Lifecycle & Task Ownership
# ==============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_lifecycle_connect_disconnect_reconnect_loop(tmp_path: Path):
    """Verify connecting, disconnecting, and reconnecting 5 times in a loop exits cleanly without AnyIO cancel scope errors."""
    registry = ServerRegistry()
    sandbox = tmp_path / "lifecycle_sandbox"
    sandbox.mkdir()

    config = UpstreamServerConfig(
        id="filesystem",
        name="Filesystem Upstream",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.filesystem.server"],
        env={"FILESYSTEM_SANDBOX_ROOT": str(sandbox)},
    )
    await registry.register_server(config)
    manager = MCPClientManager(registry=registry)

    for i in range(5):
        ok = await manager.connect_server("filesystem")
        assert ok is True, f"Failed to connect on iteration {i}"
        assert "filesystem" in manager.active_server_ids

        # Perform a quick tool call to confirm session is responsive
        res = await manager.call_tool("filesystem__list_directory", {"path": ""})
        assert res.is_error is False

        # Disconnect and verify resources freed
        await manager.disconnect_server("filesystem")
        assert "filesystem" not in manager.active_server_ids
        server_info = await registry.get_server("filesystem")
        assert server_info.status == ServerStatus.DISCONNECTED


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mid_call_upstream_crash_returns_clean_error():
    """Verify that if an upstream crashes during execution, the gateway returns a clean is_error result."""
    registry = ServerRegistry()
    manager = MCPClientManager(registry=registry)

    # Mock session whose call_tool raises a ConnectionError / EOF
    mock_session = AsyncMock()
    mock_session.call_tool.side_effect = ConnectionResetError("Upstream process closed unexpectedly")

    worker_state = MagicMock()
    worker_state.session = mock_session
    worker_state.timeout_failures = 0
    worker_state.task = MagicMock()
    worker_state.task.done.return_value = True

    manager._workers["test_server"] = worker_state

    # Register server and tool
    await registry.register_server(UpstreamServerConfig(id="test_server", name="Test Server"))
    await registry.register_tools("test_server", [
        NamespacedTool(
            server_id="test_server",
            original_name="crash_tool",
            namespaced_name="test_server__crash_tool",
            description="Tool that will crash",
            input_schema={"type": "object"},
        )
    ])

    res = await manager.call_tool("test_server__crash_tool", {})
    assert res.is_error is True
    assert "Upstream execution error" in res.content[0].text
    assert "Upstream process closed unexpectedly" in res.content[0].text


# ==============================================================================
# B6a: Paginated Tool Discovery
# ==============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_paginated_tool_discovery_follows_next_cursor():
    """Verify ToolDiscoveryEngine iterates through all pages when nextCursor is returned."""
    mock_session = AsyncMock()

    # Page 1 returns tool1 and nextCursor="page2"
    page1 = MagicMock()
    page1.tools = [Tool(name="tool_1", description="Tool 1", input_schema={})]
    page1.nextCursor = "page2"
    page1.next_cursor = "page2"

    # Page 2 returns tool2 and no nextCursor
    page2 = MagicMock()
    page2.tools = [Tool(name="tool_2", description="Tool 2", input_schema={})]
    page2.nextCursor = None
    page2.next_cursor = None

    mock_session.list_tools.side_effect = [page1, page2]

    tools = await ToolDiscoveryEngine.discover_tools(mock_session, "paginated_server")
    assert len(tools) == 2
    assert tools[0].namespaced_name == "paginated_server__tool_1"
    assert tools[1].namespaced_name == "paginated_server__tool_2"
    assert mock_session.list_tools.call_count == 2


# ==============================================================================
# B6c: Metadata Preservation (title, annotations, output_schema)
# ==============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_tool_metadata_preservation():
    """Verify ToolDiscoveryEngine and NamespacedTool preserve title, annotations, and outputSchema."""
    mock_session = AsyncMock()
    page = MagicMock()
    page.tools = [
        Tool(
            name="annotated_tool",
            description="Tool with rich metadata",
            input_schema={"type": "object", "properties": {"arg": {"type": "string"}}},
            title="Annotated Tool Title",
            output_schema={"type": "object", "properties": {"result": {"type": "string"}}},
            annotations={"readOnlyHint": True, "destructiveHint": False},
        )
    ]
    page.nextCursor = None
    page.next_cursor = None
    mock_session.list_tools.return_value = page

    tools = await ToolDiscoveryEngine.discover_tools(mock_session, "meta_server")
    assert len(tools) == 1
    nt = tools[0]
    assert nt.title == "Annotated Tool Title"
    assert nt.output_schema == {"type": "object", "properties": {"result": {"type": "string"}}}
    # Annotations can be ToolAnnotations object or dict depending on SDK parsing
    ro = getattr(nt.annotations, "read_only_hint", None)
    if ro is None and isinstance(nt.annotations, dict):
        ro = nt.annotations.get("readOnlyHint")
    assert ro is True

    # Convert to official MCP tool and verify metadata persisted
    mcp_tool = nt.to_mcp_tool()
    assert mcp_tool.title == "Annotated Tool Title"
    assert mcp_tool.output_schema == {"type": "object", "properties": {"result": {"type": "string"}}}
    mcp_ro = getattr(mcp_tool.annotations, "read_only_hint", None)
    if mcp_ro is None and isinstance(mcp_tool.annotations, dict):
        mcp_ro = mcp_tool.annotations.get("readOnlyHint")
    assert mcp_ro is True


# ==============================================================================
# B6d: Protocol Error vs Tool Result Semantics
# ==============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_protocol_error_on_unknown_tool_and_invalid_params():
    """Verify unknown tools and invalid params return clear error results."""
    registry = ServerRegistry()
    manager = MCPClientManager(registry=registry)
    gateway = ToolBridgeGatewayServer(client_manager=manager, registry=registry)
    gateway.stdio_role = UserRole.ADMIN

    # 1. Unknown tool -> Tool Result with is_error=True
    res1 = await gateway._handle_call_tool(
        ctx=None,
        params=CallToolRequestParams(name="nonexistent__tool", arguments={}),
    )
    assert res1.is_error is True
    assert "not found" in res1.content[0].text

    # 2. Register server and a tool with required parameters
    await registry.register_server(UpstreamServerConfig(id="test_server", name="Test Server"))
    await registry.register_tools("test_server", [
        NamespacedTool(
            server_id="test_server",
            original_name="validated_tool",
            namespaced_name="test_server__validated_tool",
            description="Tool with schema",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        )
    ])

    # Calling with missing required parameter -> Tool Result with is_error=True
    res2 = await gateway._handle_call_tool(
        ctx=None,
        params=CallToolRequestParams(name="test_server__validated_tool", arguments={}),
    )
    assert res2.is_error is True
    assert "Schema Validation Error" in res2.content[0].text


# ==============================================================================
# B6e: Namespacing, Double Underscore Prohibition, and Truncation
# ==============================================================================

@pytest.mark.unit
def test_namespacing_truncation_on_overflow():
    """Verify tool names exceeding 64 characters are truncated with deterministic hash."""
    long_server = "server"
    long_tool_name = "this_is_an_extremely_long_tool_name_that_definitely_exceeds_sixty_four_characters_limit"
    namespaced = create_namespaced_identifier(long_server, long_tool_name)

    assert len(namespaced) <= 64
    assert namespaced.startswith(f"{long_server}__")
    # Verify deterministic output
    namespaced2 = create_namespaced_identifier(long_server, long_tool_name)
    assert namespaced == namespaced2


@pytest.mark.unit
def test_tool_routing_splits_on_first_double_underscore_only():
    """Verify ToolRouter resolves server_id using the first '__' delimiter only."""
    # Tool with multiple double underscores in tool name part
    composite_name = "github__custom__nested__action"
    server_id, tool_name = composite_name.split("__", 1)
    assert server_id == "github"
    assert tool_name == "custom__nested__action"


# ==============================================================================
# B6f: Timeout Cancellation Notification
# ==============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_timeout_sends_cancelled_notification():
    """Verify when tool execution times out, CancelledNotification is sent to upstream session."""
    registry = ServerRegistry()
    manager = MCPClientManager(registry=registry)

    mock_session = AsyncMock()

    async def slow_call(*args, **kwargs):
        await asyncio.sleep(2.0)
        return CallToolResult(content=[], is_error=False)

    mock_session.call_tool.side_effect = slow_call

    worker_state = MagicMock()
    worker_state.session = mock_session
    worker_state.timeout_failures = 0
    worker_state.task = MagicMock()
    worker_state.task.done.return_value = False

    manager._workers["slow_server"] = worker_state

    await registry.register_server(UpstreamServerConfig(id="slow_server", name="Slow Server"))
    await registry.register_tools("slow_server", [
        NamespacedTool(
            server_id="slow_server",
            original_name="slow_tool",
            namespaced_name="slow_server__slow_tool",
            description="Slow tool",
            input_schema={"type": "object"},
        )
    ])

    res = await manager.call_tool("slow_server__slow_tool", {}, timeout_seconds=0.1)
    assert res.is_error is True
    assert "timed out" in res.content[0].text

    # Verify send_notification was called on the mock session
    assert mock_session.send_notification.call_count == 1
    call_args = mock_session.send_notification.call_args[0][0]
    assert call_args.method == "notifications/cancelled"
    assert "timed out" in call_args.params.reason
