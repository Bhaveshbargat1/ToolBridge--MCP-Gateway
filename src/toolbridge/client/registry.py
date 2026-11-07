"""Thread-safe Server Registry and Tool Catalog for ToolBridge."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Sequence
from toolbridge.models.server import ServerStatus, UpstreamServerConfig, UpstreamServerInfo
from toolbridge.models.tool import NamespacedTool


class ServerRegistry:
    """Centralized registry for upstream server configurations, runtime statuses, and tools."""

    def __init__(self) -> None:
        self._servers: dict[str, UpstreamServerInfo] = {}
        self._tools: dict[str, NamespacedTool] = {}  # Key: namespaced_name
        self._server_tools: dict[str, set[str]] = {}  # Key: server_id -> set of namespaced_names
        self._lock = asyncio.Lock()

    async def register_server(self, config: UpstreamServerConfig) -> UpstreamServerInfo:
        """Register or update an upstream server configuration."""
        async with self._lock:
            info = UpstreamServerInfo(
                config=config,
                status=ServerStatus.DISCONNECTED,
            )
            self._servers[config.id] = info
            if config.id not in self._server_tools:
                self._server_tools[config.id] = set()
            return info

    async def unregister_server(self, server_id: str) -> bool:
        """Unregister an upstream server and remove its associated tools."""
        async with self._lock:
            if server_id not in self._servers:
                return False

            # Remove server's tools
            for tool_name in self._server_tools.get(server_id, set()):
                self._tools.pop(tool_name, None)
            self._server_tools.pop(server_id, None)

            del self._servers[server_id]
            return True

    async def get_server(self, server_id: str) -> UpstreamServerInfo | None:
        """Retrieve server runtime info by ID."""
        async with self._lock:
            return self._servers.get(server_id)

    async def get_all_servers(self) -> list[UpstreamServerInfo]:
        """List all registered upstream servers."""
        async with self._lock:
            return list(self._servers.values())

    async def update_status(
        self,
        server_id: str,
        status: ServerStatus,
        error: str | None = None,
    ) -> None:
        """Update runtime connection status and error state."""
        async with self._lock:
            server = self._servers.get(server_id)
            if server:
                server.status = status
                server.last_error = error
                if status == ServerStatus.CONNECTED:
                    server.connected_at = datetime.now(timezone.utc)
                elif status in {ServerStatus.DISCONNECTED, ServerStatus.FAILED}:
                    server.connected_at = None

    async def register_tools(self, server_id: str, tools: Sequence[NamespacedTool]) -> None:
        """Register discovered tools for an upstream server, replacing any previous tools."""
        async with self._lock:
            if server_id not in self._servers:
                return

            # Clear previously registered tools for this server
            old_tools = self._server_tools.get(server_id, set())
            for t_name in old_tools:
                self._tools.pop(t_name, None)

            new_tool_names = set()
            for tool in tools:
                self._tools[tool.namespaced_name] = tool
                new_tool_names.add(tool.namespaced_name)

            self._server_tools[server_id] = new_tool_names
            self._servers[server_id].tool_count = len(new_tool_names)

    async def clear_server_tools(self, server_id: str) -> None:
        """Clear all registered tools for a disconnected server."""
        async with self._lock:
            if server_id in self._server_tools:
                for t_name in self._server_tools[server_id]:
                    self._tools.pop(t_name, None)
                self._server_tools[server_id].clear()
            if server_id in self._servers:
                self._servers[server_id].tool_count = 0

    async def get_tool(self, namespaced_name: str) -> NamespacedTool | None:
        """Lookup a tool by its namespaced name."""
        async with self._lock:
            return self._tools.get(namespaced_name)

    async def get_all_tools(self) -> list[NamespacedTool]:
        """Return all active tools across all connected servers."""
        async with self._lock:
            return list(self._tools.values())
