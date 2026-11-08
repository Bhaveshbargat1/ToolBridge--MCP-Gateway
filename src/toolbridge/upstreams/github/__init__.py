"""Controlled GitHub MCP Server package."""
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from toolbridge.upstreams.github.server import (
        ALL_GITHUB_TOOLS,
        GitHubMCPServer,
        create_github_server,
    )

__all__ = [
    "GitHubMCPServer",
    "create_github_server",
    "ALL_GITHUB_TOOLS",
]


def __getattr__(name: str) -> Any:
    """Lazy import to prevent runpy RuntimeWarnings when executed as a module."""
    if name in __all__:
        from toolbridge.upstreams.github import server
        return getattr(server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
