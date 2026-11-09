"""Integration test suite for MCPClientManager connecting to all three upstream servers."""
import asyncio
import os
import sys
from pathlib import Path
import pytest

from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import ServerStatus, TransportType, UpstreamServerConfig


@pytest.fixture
def client_env(tmp_path: Path):
    """Setup isolated manager environment with temporary sandbox and database."""
    sandbox = tmp_path / "gateway_sandbox"
    sandbox.mkdir()
    (sandbox / "demo.txt").write_text("Hello from ToolBridge Upstream Client Manager!", encoding="utf-8")

    registry = ServerRegistry()
    manager = MCPClientManager(registry=registry)
    return manager, registry, sandbox


@pytest.mark.integration
@pytest.mark.asyncio
async def test_connect_all_three_upstream_servers(client_env):
    """Verify ClientManager connects to Filesystem, Postgres, and GitHub servers simultaneously."""
    manager, registry, sandbox = client_env

    # 1. Configure Filesystem Server
    fs_config = UpstreamServerConfig(
        id="filesystem",
        name="Sandboxed Filesystem Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.filesystem.server"],
        env={"FILESYSTEM_SANDBOX_ROOT": str(sandbox)},
    )
    await registry.register_server(fs_config)

    # 2. Configure PostgreSQL Server (using SQLiteTestBackend via inline runner for hermetic test)
    pg_config = UpstreamServerConfig(
        id="postgres",
        name="PostgreSQL Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-c", """
import asyncio
from toolbridge.upstreams.postgres.server import PostgresMCPServer
from toolbridge.upstreams.postgres.backend import SQLiteTestBackend
from mcp.server.stdio import stdio_server

async def run():
    backend = SQLiteTestBackend(':memory:')
    await backend.connect()
    app = PostgresMCPServer(backend=backend)
    async with stdio_server() as (read, write):
        await app.server.run(read, write, app.server.create_initialization_options())

asyncio.run(run())
"""],
    )
    await registry.register_server(pg_config)

    # 3. Configure GitHub Server
    gh_config = UpstreamServerConfig(
        id="github",
        name="GitHub Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.github.server"],
    )
    await registry.register_server(gh_config)

    try:
        # Connect to all three servers in parallel
        results = await manager.connect_all()
        assert results["filesystem"] is True
        assert results["postgres"] is True
        assert results["github"] is True

        # Verify all statuses are CONNECTED
        servers = await registry.get_all_servers()
        for s in servers:
            assert s.status == ServerStatus.CONNECTED
            assert s.tool_count > 0

        # Verify all tools are discovered with proper namespacing
        all_tools = await registry.get_all_tools()
        namespaced_names = [t.namespaced_name for t in all_tools]

        # Filesystem tools
        assert "filesystem__read_file" in namespaced_names
        assert "filesystem__write_file" in namespaced_names

        # Postgres tools
        assert "postgres__list_tables" in namespaced_names
        assert "postgres__execute_query" in namespaced_names

        # GitHub tools
        assert "github__get_repository" in namespaced_names
        assert "github__list_issues" in namespaced_names

        # Execute tool via ClientManager
        res = await manager.call_tool("filesystem__read_file", {"path": "demo.txt"})
        assert res.is_error is False
        assert res.content[0].text == "Hello from ToolBridge Upstream Client Manager!"

        # Execute query via Postgres tool
        pg_res = await manager.call_tool(
            "postgres__execute_query",
            {"query": "SELECT count(*) as count FROM customers"},
        )
        assert pg_res.is_error is False
        assert "count" in pg_res.content[0].text

    finally:
        # Verify clean disconnection
        await manager.disconnect_all()
        assert len(manager.active_server_ids) == 0
        for s in await registry.get_all_servers():
            assert s.status == ServerStatus.DISCONNECTED


@pytest.mark.integration
@pytest.mark.asyncio
async def test_disconnected_server_and_unknown_tool_handling(client_env):
    """Verify proper error handling when calling disconnected servers or unknown tools."""
    manager, registry, _ = client_env

    # 1. Unknown tool
    res = await manager.call_tool("nonexistent__tool", {})
    assert res.is_error is True
    assert "Tool not found" in res.content[0].text

    # 2. Registered but disconnected server
    config = UpstreamServerConfig(
        id="disconnected_fs",
        name="Disconnected Server",
        transport=TransportType.STDIO,
        command="dummy",
    )
    await registry.register_server(config)

    # Fake tool registered for disconnected server
    from toolbridge.models.tool import NamespacedTool
    await registry.register_tools("disconnected_fs", [
        NamespacedTool(
            server_id="disconnected_fs",
            original_name="ping",
            namespaced_name="disconnected_fs__ping",
            description="Ping",
            input_schema={},
        )
    ])

    call_res = await manager.call_tool("disconnected_fs__ping", {})
    assert call_res.is_error is True
    assert "disconnected or unavailable" in call_res.content[0].text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_failed_connection_handling(client_env):
    """Verify attempting to connect to a failing command marks the server as FAILED without crashing."""
    manager, registry, _ = client_env

    bad_config = UpstreamServerConfig(
        id="broken_server",
        name="Broken Server",
        transport=TransportType.STDIO,
        command="non_existent_binary_12345",
        args=["--fail"],
        timeout_seconds=2.0,
    )
    await registry.register_server(bad_config)

    success = await manager.connect_server("broken_server")
    assert success is False

    info = await registry.get_server("broken_server")
    assert info.status == ServerStatus.FAILED
    assert info.last_error is not None
    assert info.tool_count == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_manager_edge_cases(client_env):
    """Verify ClientManager branches for unconfigured, disabled, and unsupported transports."""
    manager, registry, _ = client_env

    # 1. Nonexistent server connect
    assert await manager.connect_server("nonexistent") is False

    # 2. Disabled server connect
    disabled_config = UpstreamServerConfig(
        id="disabled_server",
        name="Disabled Server",
        enabled=False,
    )
    await registry.register_server(disabled_config)
    assert await manager.connect_server("disabled_server") is False

    # 3. Unsupported transport (e.g. SSE)
    sse_config = UpstreamServerConfig(
        id="sse_server",
        name="SSE Server",
        transport=TransportType.SSE,
        url="http://127.0.0.1:9000/sse",
    )
    await registry.register_server(sse_config)
    assert await manager.connect_server("sse_server") is False
    sse_info = await registry.get_server("sse_server")
    assert sse_info.status == ServerStatus.FAILED

    # 4. Stdio with missing command
    no_cmd_config = UpstreamServerConfig(
        id="no_cmd_server",
        name="No Command Server",
        transport=TransportType.STDIO,
        command="",
    )
    await registry.register_server(no_cmd_config)
    assert await manager.connect_server("no_cmd_server") is False
    no_cmd_info = await registry.get_server("no_cmd_server")
    assert no_cmd_info.status == ServerStatus.FAILED

    # 5. Disconnect nonexistent server should complete gracefully without error
    await manager.disconnect_server("nonexistent")

    # 6. Call unknown tool
    unknown_res = await manager.call_tool("unknown__tool", {})
    assert unknown_res.is_error is True
    assert "Tool not found" in unknown_res.content[0].text

