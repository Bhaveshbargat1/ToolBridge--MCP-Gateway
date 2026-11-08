"""Controlled Filesystem MCP Server package."""
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from toolbridge.upstreams.filesystem.server import (
        ALL_FILESYSTEM_TOOLS,
        FilesystemMCPServer,
        create_filesystem_server,
    )

__all__ = [
    "FilesystemMCPServer",
    "create_filesystem_server",
    "ALL_FILESYSTEM_TOOLS",
]


def __getattr__(name: str) -> Any:
    """Lazy import to prevent runpy RuntimeWarnings when executed as a module."""
    if name in __all__:
        from toolbridge.upstreams.filesystem import server
        return getattr(server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
