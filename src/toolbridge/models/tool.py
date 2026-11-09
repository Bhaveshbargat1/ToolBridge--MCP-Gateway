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
    title: str | None = Field(default=None, description="Human-readable title")
    output_schema: dict[str, Any] | None = Field(default=None, description="Optional output schema")
    annotations: Any = Field(default=None, description="Tool annotations (e.g. readOnlyHint, destructiveHint)")

    def to_mcp_tool(self) -> Tool:
        """Convert to official MCP SDK v2 Tool object, preserving metadata."""
        kwargs: dict[str, Any] = {
            "name": self.namespaced_name,
            "description": f"[{self.server_id}] {self.description}".strip(),
            "input_schema": self.input_schema,
        }
        if self.title is not None:
            kwargs["title"] = self.title
        if self.output_schema is not None:
            kwargs["output_schema"] = self.output_schema
        if self.annotations is not None:
            kwargs["annotations"] = self.annotations

        return Tool(**kwargs)
