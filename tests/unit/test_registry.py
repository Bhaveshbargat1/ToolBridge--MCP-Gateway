"""Unit tests for ServerRegistry and ToolDiscoveryEngine."""
import pytest
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import ServerStatus, TransportType, UpstreamServerConfig
from toolbridge.models.tool import NamespacedTool


@pytest.fixture
def registry() -> ServerRegistry:
    return ServerRegistry()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_register_and_get_server(registry: ServerRegistry):
    """Verify server registration and retrieval."""
    config = UpstreamServerConfig(
        id="test_server",
        name="Test Upstream Server",
        transport=TransportType.STDIO,
        command="python",
        args=["-m", "dummy"],
    )
    info = await registry.register_server(config)
    assert info.config.id == "test_server"
    assert info.status == ServerStatus.DISCONNECTED

    fetched = await registry.get_server("test_server")
    assert fetched is not None
    assert fetched.config.name == "Test Upstream Server"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_update_server_status(registry: ServerRegistry):
    """Verify updating server lifecycle statuses."""
    config = UpstreamServerConfig(id="s1", name="Server 1")
    await registry.register_server(config)

    await registry.update_status("s1", ServerStatus.CONNECTED)
    s = await registry.get_server("s1")
    assert s.status == ServerStatus.CONNECTED
    assert s.connected_at is not None

    await registry.update_status("s1", ServerStatus.FAILED, error="Connection refused")
    s = await registry.get_server("s1")
    assert s.status == ServerStatus.FAILED
    assert s.last_error == "Connection refused"
    assert s.connected_at is None


@pytest.mark.unit
@pytest.mark.asyncio
async def test_register_and_lookup_tools(registry: ServerRegistry):
    """Verify tool registration, namespaced lookup, and tool counts."""
    config = UpstreamServerConfig(id="fs", name="Filesystem Server")
    await registry.register_server(config)

    tools = [
        NamespacedTool(
            server_id="fs",
            original_name="read_file",
            namespaced_name="fs__read_file",
            description="Read file",
            input_schema={"type": "object"},
        ),
        NamespacedTool(
            server_id="fs",
            original_name="write_file",
            namespaced_name="fs__write_file",
            description="Write file",
            input_schema={"type": "object"},
        ),
    ]

    await registry.register_tools("fs", tools)

    s = await registry.get_server("fs")
    assert s.tool_count == 2

    tool = await registry.get_tool("fs__read_file")
    assert tool is not None
    assert tool.original_name == "read_file"
    assert tool.server_id == "fs"

    all_tools = await registry.get_all_tools()
    assert len(all_tools) == 2


@pytest.mark.unit
@pytest.mark.asyncio
async def test_clear_tools_and_unregister_server(registry: ServerRegistry):
    """Verify clearing tools and unregistering servers cleans up the catalog."""
    config = UpstreamServerConfig(id="gh", name="GitHub Server")
    await registry.register_server(config)

    tool = NamespacedTool(
        server_id="gh",
        original_name="get_repo",
        namespaced_name="gh__get_repo",
        description="Get repo",
        input_schema={},
    )
    await registry.register_tools("gh", [tool])
    assert await registry.get_tool("gh__get_repo") is not None

    # Clear tools
    await registry.clear_server_tools("gh")
    assert await registry.get_tool("gh__get_repo") is None
    s = await registry.get_server("gh")
    assert s.tool_count == 0

    # Unregister
    removed = await registry.unregister_server("gh")
    assert removed is True
    assert await registry.get_server("gh") is None
