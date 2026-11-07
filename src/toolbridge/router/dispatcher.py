"""Dynamic Tool Router and Proxy Dispatcher for ToolBridge Gateway."""
from __future__ import annotations

import logging
from typing import Any
import jsonschema
from jsonschema.exceptions import ValidationError

from mcp.types import CallToolResult, TextContent

from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry

logger = logging.getLogger(__name__)


class ToolRouter:
    """Routes downstream tool calls to appropriate upstream servers with validation."""

    def __init__(self, client_manager: MCPClientManager, registry: ServerRegistry) -> None:
        self.client_manager = client_manager
        self.registry = registry

    async def dispatch(
        self,
        namespaced_tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> CallToolResult:
        """Validate input schema and proxy tool call to the designated upstream server.

        Args:
            namespaced_tool_name: The namespaced tool name (e.g. 'filesystem__read_file').
            arguments: Input arguments dictionary provided by downstream client.

        Returns:
            CallToolResult containing result data or formatted error message.
        """
        args = arguments or {}

        # 1. Lookup Tool in Registry
        tool = await self.registry.get_tool(namespaced_tool_name)
        if not tool:
            logger.warning(f"Routing rejected: Unknown tool '{namespaced_tool_name}'")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Gateway Error: Tool '{namespaced_tool_name}' not found.")],
                is_error=True,
            )

        # 2. Pre-flight JSON Schema Validation
        if tool.input_schema:
            try:
                jsonschema.validate(instance=args, schema=tool.input_schema)
            except ValidationError as e:
                logger.warning(f"Schema validation failed for '{namespaced_tool_name}': {e.message}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Schema Validation Error for '{namespaced_tool_name}': {e.message}")],
                    is_error=True,
                )
            except Exception as e:
                logger.error(f"Unexpected schema evaluation error for '{namespaced_tool_name}': {e}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Schema Error: {e}")],
                    is_error=True,
                )

        # 3. Route to Upstream via Client Manager
        logger.info(f"Proxying '{namespaced_tool_name}' -> server '{tool.server_id}' (tool: '{tool.original_name}')")
        try:
            result = await self.client_manager.call_tool(namespaced_tool_name, args)
            return result
        except Exception as e:
            logger.error(f"Gateway proxy error invoking '{namespaced_tool_name}': {e}", exc_info=True)
            return CallToolResult(
                content=[TextContent(type="text", text=f"Gateway Invocation Error on '{namespaced_tool_name}': {e}")],
                is_error=True,
            )
