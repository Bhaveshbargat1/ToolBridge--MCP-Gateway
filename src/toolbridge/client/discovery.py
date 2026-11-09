"""Dynamic Tool Discovery Engine for introspecting and namespacing upstream MCP tools."""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any
from mcp.client.session import ClientSession
from toolbridge.models.tool import NamespacedTool

logger = logging.getLogger(__name__)

SAFE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def create_namespaced_identifier(server_id: str, original_name: str) -> str:
    """Create a validated namespaced tool identifier in the format <server_id>__<original_name>.

    Truncates with deterministic hash if the total length exceeds 64 characters.
    """
    candidate = f"{server_id}__{original_name}"
    if len(candidate) > 64:
        # Truncate with sha256 hash suffix to ensure uniqueness within 64 chars
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:8]
        prefix = candidate[:55]
        candidate = f"{prefix}_{digest}"

    # Replace any disallowed characters with underscore
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", candidate)
    if not SAFE_IDENTIFIER_RE.match(sanitized):
        sanitized = sanitized[:64]
    return sanitized


class ToolDiscoveryEngine:
    """Interrogates active upstream MCP sessions to discover, validate, and namespace tools."""

    @staticmethod
    async def discover_tools(session: ClientSession, server_id: str) -> list[NamespacedTool]:
        """Fetch all tools exposed by an active MCP session and apply namespacing.

        Follows cursor pagination until all pages are exhausted.
        Preserves metadata: title, annotations, outputSchema.
        """
        logger.info(f"Discovering tools for upstream server: '{server_id}'...")
        discovered: list[NamespacedTool] = []
        cursor: str | None = None

        while True:
            if cursor:
                tools_response = await session.list_tools(cursor=cursor)
            else:
                tools_response = await session.list_tools()

            for tool in tools_response.tools:
                schema = getattr(tool, "input_schema", None)
                if not isinstance(schema, dict):
                    schema = {"type": "object", "properties": {}}

                namespaced_name = create_namespaced_identifier(server_id, tool.name)

                namespaced_tool = NamespacedTool(
                    server_id=server_id,
                    original_name=tool.name,
                    namespaced_name=namespaced_name,
                    description=tool.description or "",
                    input_schema=schema,
                    title=getattr(tool, "title", None),
                    output_schema=getattr(tool, "output_schema", None),
                    annotations=getattr(tool, "annotations", None),
                )
                discovered.append(namespaced_tool)
                logger.debug(f"Discovered tool: '{namespaced_name}' (origin: '{tool.name}')")

            # Check next cursor for pagination
            cursor = getattr(tools_response, "nextCursor", None) or getattr(tools_response, "next_cursor", None)
            if not cursor:
                break

        logger.info(f"Discovered {len(discovered)} tools for server '{server_id}'.")
        return discovered
