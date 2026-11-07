"""Domain models representing upstream MCP server configurations and runtime status."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class TransportType(str, Enum):
    """Supported MCP upstream transport types."""
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"


class ServerStatus(str, Enum):
    """Runtime lifecycle states for an upstream MCP server."""
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    UNHEALTHY = "UNHEALTHY"
    FAILED = "FAILED"


class UpstreamServerConfig(BaseModel):
    """Static configuration for connecting to an upstream MCP server."""
    id: str = Field(..., description="Unique alphanumeric identifier for the server (e.g. 'github', 'fs')")
    name: str = Field(..., description="Human-readable server name")
    transport: TransportType = Field(default=TransportType.STDIO, description="Transport type")
    command: str | None = Field(default=None, description="Executable command for stdio transport")
    args: list[str] = Field(default_factory=list, description="Command arguments for stdio transport")
    env: dict[str, str] = Field(default_factory=dict, description="Environment variables passed to subprocess")
    url: str | None = Field(default=None, description="HTTP/SSE URL for network transports")
    enabled: bool = Field(default=True, description="Whether the server is enabled in the gateway")
    timeout_seconds: float = Field(default=30.0, description="Default invocation timeout in seconds")


class UpstreamServerInfo(BaseModel):
    """Dynamic runtime state of an upstream MCP server."""
    config: UpstreamServerConfig
    status: ServerStatus = Field(default=ServerStatus.DISCONNECTED)
    connected_at: datetime | None = None
    last_error: str | None = None
    tool_count: int = Field(default=0)
