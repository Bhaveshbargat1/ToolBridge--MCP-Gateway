"""Downstream Gateway MCP Server: Unified entrance for downstream AI applications."""
from __future__ import annotations

import asyncio
import logging
import os
import sys

from mcp.server.lowlevel.server import NotificationOptions, Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ErrorData,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)

from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import TransportType, UpstreamServerConfig
from toolbridge.router.dispatcher import ToolRouter
from toolbridge.security.guards.filesystem import resolve_sandbox_root
from toolbridge.security.policy import PolicyEngine, UserRole

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

        # Determine effective role for stdio downstream client (default: readonly, never default to admin)
        raw_role = os.environ.get("TOOLBRIDGE_STDIO_ROLE", "readonly").strip().lower()
        if raw_role == "admin":
            self.stdio_role = UserRole.ADMIN
        elif raw_role == "operator":
            self.stdio_role = UserRole.OPERATOR
        else:
            self.stdio_role = UserRole.READONLY

        sys.stderr.write(f"[ToolBridge Gateway] Effective stdio client role: '{self.stdio_role.value}'\n")
        sys.stderr.flush()

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
        """Dynamically aggregate and expose all namespaced tools from active upstream servers.

        Implements cursor pagination support per MCP protocol specification.
        """
        namespaced_tools = await self.registry.get_all_tools()
        mcp_tools = [t.to_mcp_tool() for t in namespaced_tools]
        logger.debug(f"Exposing {len(mcp_tools)} aggregated tools to downstream client.")

        page_size = 50
        offset = 0
        if params and params.cursor:
            try:
                offset = int(params.cursor)
            except ValueError:
                offset = 0

        paged_tools = mcp_tools[offset : offset + page_size]
        next_cursor = str(offset + page_size) if (offset + page_size) < len(mcp_tools) else None

        return ListToolsResult(tools=paged_tools, nextCursor=next_cursor)

    async def _handle_call_tool(
        self,
        ctx: ServerRequestContext,
        params: CallToolRequestParams,
    ) -> CallToolResult:
        """Intercept downstream tool calls and dispatch through the security and proxy router."""
        logger.info(f"Downstream client requested tool: '{params.name}'")

        # 1. Enforce RBAC for stdio downstream client
        authorized, reason = PolicyEngine.is_authorized(self.stdio_role, params.name)
        if not authorized:
            logger.warning(
                f"Policy denied stdio tool call '{params.name}' for role '{self.stdio_role.value}': {reason}"
            )
            return CallToolResult(
                is_error=True,
                content=[TextContent(type="text", text=f"Policy Authorization Denied: {reason}")],
            )

        # 2. Dispatch through Router (pre-flight schema validation + upstream invocation)
        try:
            return await self.router.dispatch(
                namespaced_tool_name=params.name,
                arguments=params.arguments or {},
            )
        except Exception as e:
            logger.error(f"Unexpected gateway dispatch error: {e}", exc_info=True)
            return CallToolResult(
                is_error=True,
                content=[TextContent(type="text", text=f"Tool Execution Failed: {e}")],
            )


def configure_default_upstreams(registry: ServerRegistry) -> None:
    """Register standard upstream server configurations (Filesystem, Postgres, GitHub)."""
    # 1. Filesystem Server
    fs_sandbox = str(resolve_sandbox_root())
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
    )
    asyncio.run(registry.register_server(pg_config))

    # 3. GitHub Server
    gh_config = UpstreamServerConfig(
        id="github",
        name="GitHub Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.github.server"],
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", "")},
    )
    asyncio.run(registry.register_server(gh_config))


async def run_gateway_stdio() -> None:
    """Main lifecycle coroutine running downstream MCP server over standard I/O."""
    # Ensure all logging goes to stderr so stdio JSON-RPC on stdout is not corrupted
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)

    registry = ServerRegistry()
    fs_sandbox = str(resolve_sandbox_root())
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
            # Advertise tools.listChanged downstream
            init_options = gateway_app.server.create_initialization_options(
                notification_options=NotificationOptions(tools_changed=True)
            )
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
