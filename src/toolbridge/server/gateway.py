"""Downstream Gateway MCP Server: Unified entrance for downstream AI applications."""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any

from mcp.server.lowlevel.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
)

from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import TransportType, UpstreamServerConfig
from toolbridge.router.dispatcher import ToolRouter

logger = logging.getLogger("toolbridge.gateway")


class ToolBridgeGatewayServer:
    """Downstream MCP Gateway Server exposing aggregated, namespaced upstream tools."""

    def __init__(
        self,
        client_manager: MCPClientManager,
        registry: ServerRegistry | None = None,
        name: str = "ToolBridge Enterprise Gateway",
        version: str = "0.1.0",
    ) -> None:
        self.client_manager = client_manager
        self.registry = registry or client_manager.registry
        self.router = ToolRouter(client_manager=self.client_manager, registry=self.registry)

        self.server = Server(
            name=name,
            version=version,
            on_list_tools=self._handle_list_tools,
            on_call_tool=self._handle_call_tool,
        )

    async def _handle_list_tools(
        self,
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        """Dynamically aggregate and expose all namespaced tools from active upstream servers."""
        namespaced_tools = await self.registry.get_all_tools()
        mcp_tools = [t.to_mcp_tool() for t in namespaced_tools]
        logger.debug(f"Exposing {len(mcp_tools)} aggregated tools to downstream client.")
        return ListToolsResult(tools=mcp_tools)

    async def _handle_call_tool(
        self,
        ctx: ServerRequestContext,
        params: CallToolRequestParams,
    ) -> CallToolResult:
        """Intercept downstream tool calls and dispatch through the security and proxy router."""
        logger.info(f"Downstream client requested tool: '{params.name}'")
        return await self.router.dispatch(
            namespaced_tool_name=params.name,
            arguments=params.arguments or {},
        )


def configure_default_upstreams(registry: ServerRegistry) -> None:
    """Register standard upstream server configurations (Filesystem, Postgres, GitHub)."""
    # 1. Filesystem Server
    fs_sandbox = os.environ.get("FILESYSTEM_SANDBOX_ROOT", "./workspace_sandbox")
    fs_config = UpstreamServerConfig(
        id="filesystem",
        name="Sandboxed Filesystem Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.filesystem.server"],
        env={"FILESYSTEM_SANDBOX_ROOT": fs_sandbox},
    )
    asyncio.run(registry.register_server(fs_config))

    # 2. PostgreSQL Server
    pg_config = UpstreamServerConfig(
        id="postgres",
        name="PostgreSQL Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.postgres.server"],
        env={
            "POSTGRES_READONLY_HOST": os.environ.get("POSTGRES_READONLY_HOST", "localhost"),
            "POSTGRES_READONLY_PORT": os.environ.get("POSTGRES_READONLY_PORT", "5432"),
            "POSTGRES_READONLY_DB": os.environ.get("POSTGRES_READONLY_DB", "toolbridge_demo"),
            "POSTGRES_READONLY_USER": os.environ.get("POSTGRES_READONLY_USER", "mcp_readonly"),
            "POSTGRES_READONLY_PASSWORD": os.environ.get("POSTGRES_READONLY_PASSWORD", ""),
        },
    )
    asyncio.run(registry.register_server(pg_config))

    # 3. GitHub Server
    gh_config = UpstreamServerConfig(
        id="github",
        name="GitHub Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.github.server"],
        env={
            "GITHUB_PERSONAL_ACCESS_TOKEN": os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", ""),
        },
    )
    asyncio.run(registry.register_server(gh_config))


async def run_gateway_stdio() -> None:
    """Boot all upstream servers and run the downstream Gateway server over stdio."""
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    logger.info("Starting ToolBridge Gateway Server...")

    registry = ServerRegistry()
    # Configure upstreams asynchronously
    fs_sandbox = os.environ.get("FILESYSTEM_SANDBOX_ROOT", "./workspace_sandbox")
    await registry.register_server(UpstreamServerConfig(
        id="filesystem",
        name="Sandboxed Filesystem Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.filesystem.server"],
        env={"FILESYSTEM_SANDBOX_ROOT": fs_sandbox},
    ))
    await registry.register_server(UpstreamServerConfig(
        id="postgres",
        name="PostgreSQL Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.postgres.server"],
    ))
    await registry.register_server(UpstreamServerConfig(
        id="github",
        name="GitHub Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.github.server"],
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", "")},
    ))

    manager = MCPClientManager(registry=registry)
    # Connect upstreams
    logger.info("Connecting to upstream MCP servers...")
    conn_results = await manager.connect_all()
    for s_id, ok in conn_results.items():
        logger.info(f"Upstream '{s_id}': {'CONNECTED' if ok else 'FAILED'}")

    gateway_app = ToolBridgeGatewayServer(client_manager=manager, registry=registry)

    try:
        async with stdio_server() as (read_stream, write_stream):
            init_options = gateway_app.server.create_initialization_options()
            logger.info("ToolBridge Gateway ready for downstream AI clients.")
            await gateway_app.server.run(read_stream, write_stream, init_options)
    finally:
        logger.info("Shutting down ToolBridge Gateway and disconnecting upstreams...")
        await manager.disconnect_all()


def main() -> None:
    """CLI Entrypoint."""
    asyncio.run(run_gateway_stdio())


if __name__ == "__main__":
    main()
