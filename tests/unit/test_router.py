"""Unit tests for ToolRouter pre-flight schema validation and routing."""
import pytest
from mcp.types import CallToolResult, TextContent

from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import UpstreamServerConfig
from toolbridge.models.tool import NamespacedTool
from toolbridge.router.dispatcher import ToolRouter


@pytest.fixture
def router_env():
    registry = ServerRegistry()
    manager = MCPClientManager(registry=registry)
    router = ToolRouter(client_manager=manager, registry=registry)
    return router, manager, registry


@pytest.mark.unit
@pytest.mark.asyncio
async def test_router_unknown_tool_rejection(router_env):
    """Verify router immediately rejects unknown tool names."""
    router, _, _ = router_env
    res = await router.dispatch("nonexistent__tool", {})
    assert res.is_error is True
    assert "Tool 'nonexistent__tool' not found" in res.content[0].text


@pytest.mark.unit
@pytest.mark.asyncio
async def test_router_schema_validation_rejection(router_env):
    """Verify router rejects calls that violate the tool's JSON schema before calling upstream."""
    router, _, registry = router_env

    # Register a tool requiring 'path' (string) and 'count' (integer)
    tool = NamespacedTool(
        server_id="test_server",
        original_name="test_tool",
        namespaced_name="test_server__test_tool",
        description="A schema-validated tool",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "count": {"type": "integer"},
            },
            "required": ["path", "count"],
        },
    )
    await registry.register_server(UpstreamServerConfig(id="test_server", name="Test"))
    await registry.register_tools("test_server", [tool])

    # 1. Missing required parameter 'count'
    missing_res = await router.dispatch("test_server__test_tool", {"path": "hello.txt"})
    assert missing_res.is_error is True
    assert "Schema Validation Error" in missing_res.content[0].text
    assert "'count' is a required property" in missing_res.content[0].text

    # 2. Invalid data type: string instead of integer for 'count'
    type_res = await router.dispatch("test_server__test_tool", {"path": "hello.txt", "count": "not_an_int"})
    assert type_res.is_error is True
    assert "Schema Validation Error" in type_res.content[0].text
    assert "is not of type 'integer'" in type_res.content[0].text
