"""MCP Client Manager for handling upstream server lifecycles, pooling, and invocations."""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import AsyncExitStack
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import CallToolResult, TextContent

from toolbridge.client.discovery import ToolDiscoveryEngine
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import ServerStatus, TransportType, UpstreamServerConfig

logger = logging.getLogger(__name__)


class MCPClientManager:
    """Manages the connection lifecycle, discovery, and execution for all upstream MCP servers."""

    def __init__(self, registry: ServerRegistry | None = None) -> None:
        self.registry = registry or ServerRegistry()
        self._stacks: dict[str, AsyncExitStack] = {}
        self._sessions: dict[str, ClientSession] = {}
        self._lock = asyncio.Lock()

    @property
    def active_server_ids(self) -> list[str]:
        """Return list of server IDs with active sessions."""
        return list(self._sessions.keys())

    async def connect_server(self, server_id: str) -> bool:
        """Establish an MCP connection with an upstream server and discover its tools.

        Args:
            server_id: Identifier of the registered server.

        Returns:
            True if connection and discovery succeeded, False otherwise.
        """
        async with self._lock:
            server_info = await self.registry.get_server(server_id)
            if not server_info:
                logger.error(f"Cannot connect: Server '{server_id}' is not registered.")
                return False

            config = server_info.config
            if not config.enabled:
                logger.info(f"Skipping server '{server_id}' (disabled in configuration).")
                return False

            # If already connected, disconnect first for clean reconnection
            if server_id in self._stacks:
                await self._disconnect_server_internal(server_id)

            await self.registry.update_status(server_id, ServerStatus.CONNECTING)
            stack = AsyncExitStack()

            try:
                if config.transport == TransportType.STDIO:
                    if not config.command:
                        raise ValueError(f"Server '{server_id}' specifies stdio transport but no command.")

                    env = {**os.environ, **config.env, "PYTHONUNBUFFERED": "1"}
                    params = StdioServerParameters(
                        command=config.command,
                        args=config.args,
                        env=env,
                    )
                    read_stream, write_stream = await stack.enter_async_context(stdio_client(params))
                else:
                    raise NotImplementedError(
                        f"Transport '{config.transport}' is not yet supported in ClientManager."
                    )

                # Initialize MCP Client Session
                session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
                await asyncio.wait_for(session.initialize(), timeout=config.timeout_seconds)

                # Introspect and discover tools
                tools = await ToolDiscoveryEngine.discover_tools(session, server_id)

                self._stacks[server_id] = stack
                self._sessions[server_id] = session

                await self.registry.update_status(server_id, ServerStatus.CONNECTED)
                await self.registry.register_tools(server_id, tools)
                logger.info(f"Successfully connected to upstream server '{server_id}' with {len(tools)} tools.")
                return True

            except Exception as e:
                logger.error(f"Failed to connect to upstream server '{server_id}': {e}", exc_info=True)
                await stack.aclose()
                await self.registry.update_status(server_id, ServerStatus.FAILED, error=str(e))
                await self.registry.clear_server_tools(server_id)
                return False

    async def connect_all(self) -> dict[str, bool]:
        """Attempt to connect to all enabled upstream servers in parallel."""
        servers = await self.registry.get_all_servers()
        tasks = [self.connect_server(s.config.id) for s in servers if s.config.enabled]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return {s.config.id: res for s, res in zip(servers, results) if s.config.enabled}

    async def disconnect_server(self, server_id: str) -> None:
        """Disconnect an active upstream server and clean up its resources."""
        async with self._lock:
            await self._disconnect_server_internal(server_id)

    async def _disconnect_server_internal(self, server_id: str) -> None:
        """Internal helper to clean up an upstream server context stack."""
        self._sessions.pop(server_id, None)
        stack = self._stacks.pop(server_id, None)
        if stack:
            try:
                await stack.aclose()
            except Exception as e:
                logger.warning(f"Error closing context stack for '{server_id}': {e}")

        await self.registry.update_status(server_id, ServerStatus.DISCONNECTED)
        await self.registry.clear_server_tools(server_id)
        logger.info(f"Disconnected server '{server_id}'.")

    async def disconnect_all(self) -> None:
        """Disconnect all active upstream servers."""
        async with self._lock:
            for server_id in list(self._stacks.keys()):
                await self._disconnect_server_internal(server_id)

    async def call_tool(
        self,
        namespaced_tool_name: str,
        arguments: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
    ) -> CallToolResult:
        """Route an execution request to the appropriate upstream server by namespaced tool name.

        Args:
            namespaced_tool_name: The namespaced name (e.g. 'filesystem__read_file').
            arguments: Arguments dictionary for the tool invocation.
            timeout_seconds: Optional timeout override.

        Returns:
            CallToolResult containing the execution outcome or error.
        """
        tool = await self.registry.get_tool(namespaced_tool_name)
        if not tool:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Tool not found: '{namespaced_tool_name}'")],
                is_error=True,
            )

        server_id = tool.server_id
        session = self._sessions.get(server_id)
        if not session:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Upstream server '{server_id}' is disconnected or unavailable.")],
                is_error=True,
            )

        server_info = await self.registry.get_server(server_id)
        timeout = timeout_seconds or (server_info.config.timeout_seconds if server_info else 30.0)

        try:
            result = await asyncio.wait_for(
                session.call_tool(tool.original_name, arguments or {}),
                timeout=timeout,
            )
            return result
        except asyncio.TimeoutError:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Tool execution timed out after {timeout} seconds.")],
                is_error=True,
            )
        except Exception as e:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Upstream execution error on '{server_id}': {e}")],
                is_error=True,
            )
