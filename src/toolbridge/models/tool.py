"""Domain models for dynamic tool definitions and namespacing."""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field
from mcp.types import Tool


class NamespacedTool(BaseModel):
    """An upstream tool wrapped with its gateway namespace identifier."""
    server_id: str = Field(..., description="ID of the upstream server hosting this tool")
    original_name: str = Field(..., description="Original name declared by the upstream server")
    namespaced_name: str = Field(..., description="Namespaced unique identifier: <server_id>__<original_name>")
    description: str = Field(default="", description="Tool documentation / description")
    input_schema: dict[str, Any] = Field(default_factory=dict, description="JSON Schema for tool arguments")

    def to_mcp_tool(self) -> Tool:
        """Convert to official MCP SDK v2 Tool object."""
        return Tool(
            name=self.namespaced_name,
            description=f"[{self.server_id}] {self.description}".strip(),
            input_schema=self.input_schema,
        )
