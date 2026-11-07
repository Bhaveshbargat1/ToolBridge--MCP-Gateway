"""End-to-End integration test for downstream MCP client connecting solely to ToolBridge Gateway."""
import asyncio
import json
import os
import sys
from pathlib import Path
import pytest

from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import TransportType, UpstreamServerConfig
from toolbridge.server.gateway import ToolBridgeGatewayServer


@pytest.mark.integration
@pytest.mark.asyncio
async def test_downstream_client_e2e_gateway_proxy(tmp_path: Path):
    """Verify that a separate downstream MCP client can discover and execute all tools through ToolBridge alone."""
    sandbox = tmp_path / "downstream_sandbox"
    sandbox.mkdir()
    (sandbox / "welcome.txt").write_text("Hello from ToolBridge Gateway Unified Interface!", encoding="utf-8")

    # Gateway script to run in child subprocess over stdio
    gateway_script = f"""
import asyncio
import os
import sys
from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import UpstreamServerConfig, TransportType
from toolbridge.server.gateway import ToolBridgeGatewayServer
from mcp.server.stdio import stdio_server

async def run():
    registry = ServerRegistry()

    # 1. Register Filesystem
    await registry.register_server(UpstreamServerConfig(
        id="filesystem",
        name="Filesystem Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.filesystem.server"],
        env={{"FILESYSTEM_SANDBOX_ROOT": r"{sandbox}"}},
    ))

    # 2. Register PostgreSQL (with SQLiteTestBackend)
    await registry.register_server(UpstreamServerConfig(
        id="postgres",
        name="PostgreSQL Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-c", '''
import asyncio
from toolbridge.upstreams.postgres.server import PostgresMCPServer
from toolbridge.upstreams.postgres.backend import SQLiteTestBackend
from mcp.server.stdio import stdio_server

async def main():
    backend = SQLiteTestBackend(":memory:")
    await backend.connect()
    app = PostgresMCPServer(backend=backend)
    async with stdio_server() as (r, w):
        await app.server.run(r, w, app.server.create_initialization_options())

asyncio.run(main())
'''],
    ))

    # 3. Register GitHub
    await registry.register_server(UpstreamServerConfig(
        id="github",
        name="GitHub Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.github.server"],
    ))

    manager = MCPClientManager(registry=registry)
    await manager.connect_all()

    gateway_server = ToolBridgeGatewayServer(client_manager=manager, registry=registry)

    try:
        async with stdio_server() as (read, write):
            init_opts = gateway_server.server.create_initialization_options()
            await gateway_server.server.run(read, write, init_opts)
    finally:
        await manager.disconnect_all()

asyncio.run(run())
"""

    gateway_params = StdioServerParameters(
        command=sys.executable,
        args=["-c", gateway_script],
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    # Downstream MCP Client connects ONLY to ToolBridge Gateway
    async with stdio_client(gateway_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # 1. Protocol Handshake with ToolBridge
            init_result = await session.initialize()
            assert init_result.server_info.name == "ToolBridge Enterprise Gateway"

            # 2. Dynamic Tool Discovery through ToolBridge alone
            tools_response = await session.list_tools()
            tool_names = [t.name for t in tools_response.tools]

            # Verify namespaced tools from all upstreams are exposed
            assert "filesystem__read_file" in tool_names
            assert "filesystem__write_file" in tool_names
            assert "postgres__list_tables" in tool_names
            assert "postgres__execute_query" in tool_names
            assert "github__get_repository" in tool_names
            assert "github__list_issues" in tool_names

            # Verify input schemas and descriptions are preserved
            fs_read_tool = next(t for t in tools_response.tools if t.name == "filesystem__read_file")
            assert "path" in fs_read_tool.input_schema["properties"]
            assert fs_read_tool.input_schema["required"] == ["path"]
            assert "[filesystem]" in fs_read_tool.description

            # 3. Tool Execution: read_file through Gateway
            read_result = await session.call_tool(
                "filesystem__read_file",
                {"path": "welcome.txt"},
            )
            assert read_result.is_error is False
            assert read_result.content[0].text == "Hello from ToolBridge Gateway Unified Interface!"

            # 4. Tool Execution: write_file through Gateway
            write_result = await session.call_tool(
                "filesystem__write_file",
                {
                    "path": "ai_agent_output.txt",
                    "content": "Generated by downstream AI client via ToolBridge Gateway.",
                },
            )
            assert write_result.is_error is False

            # Verify written file exists in the sandbox
            created_file = sandbox / "ai_agent_output.txt"
            assert created_file.exists()
            assert created_file.read_text(encoding="utf-8") == "Generated by downstream AI client via ToolBridge Gateway."

            # 5. Tool Execution: PostgreSQL query through Gateway
            pg_result = await session.call_tool(
                "postgres__execute_query",
                {"query": "SELECT id, name FROM customers WHERE id = $1", "parameters": [1]},
            )
            assert pg_result.is_error is False
            assert "Alice Smith" in pg_result.content[0].text

            # 6. Error Handling: Security Path Traversal through Gateway
            traversal_result = await session.call_tool(
                "filesystem__read_file",
                {"path": "../../outside_secret.key"},
            )
            assert traversal_result.is_error is True
            assert "Security Violation" in traversal_result.content[0].text

            # 7. Error Handling: Pre-flight Schema Validation Error through Gateway
            schema_err_result = await session.call_tool(
                "filesystem__write_file",
                {"invalid_argument": 123},  # Missing required 'path' and 'content'
            )
            assert schema_err_result.is_error is True
            assert "Schema Validation Error" in schema_err_result.content[0].text

            # 8. Error Handling: Non-existent tool call through Gateway
            unknown_result = await session.call_tool(
                "nonexistent__tool",
                {},
            )
            assert unknown_result.is_error is True
            assert "not found" in unknown_result.content[0].text
