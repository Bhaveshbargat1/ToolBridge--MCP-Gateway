"""Dynamic Tool Discovery Engine for introspecting and namespacing upstream MCP tools."""
from __future__ import annotations

import logging
from typing import Any
from mcp.client.session import ClientSession
from toolbridge.models.tool import NamespacedTool

logger = logging.getLogger(__name__)


class ToolDiscoveryEngine:
    """Interrogates active upstream MCP sessions to discover, validate, and namespace tools."""

    @staticmethod
    async def discover_tools(session: ClientSession, server_id: str) -> list[NamespacedTool]:
        """Fetch all tools exposed by an active MCP session and apply namespacing.

        Args:
            session: An initialized, active ClientSession.
            server_id: The identifier of the server (e.g. 'github', 'filesystem').

        Returns:
            A list of validated NamespacedTool instances.
        """
        logger.info(f"Discovering tools for upstream server: '{server_id}'...")
        tools_response = await session.list_tools()

        discovered: list[NamespacedTool] = []
        for tool in tools_response.tools:
            # Handle schema extraction across SDK representations
            schema = tool.input_schema if hasattr(tool, "input_schema") else {}
            if not isinstance(schema, dict):
                schema = {"type": "object", "properties": {}}

            # Enforce deterministic namespacing: <server_id>__<original_name>
            namespaced_name = f"{server_id}__{tool.name}"

            namespaced_tool = NamespacedTool(
                server_id=server_id,
                original_name=tool.name,
                namespaced_name=namespaced_name,
                description=tool.description or "",
                input_schema=schema,
            )
            discovered.append(namespaced_tool)
            logger.debug(f"Discovered tool: '{namespaced_name}' (origin: '{tool.name}')")

        logger.info(f"Discovered {len(discovered)} tools for server '{server_id}'.")
        return discovered
