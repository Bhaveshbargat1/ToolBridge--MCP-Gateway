"""PostgreSQL MCP Server package."""
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from toolbridge.upstreams.postgres.server import (
        ALL_POSTGRES_TOOLS,
        PostgresMCPServer,
        create_postgres_server,
    )
    from toolbridge.upstreams.postgres.backend import (
        DatabaseBackend,
        DatabaseConnectionError,
        DatabaseQueryTimeoutError,
        PostgresBackend,
        SQLiteTestBackend,
    )

__all__ = [
    "PostgresMCPServer",
    "create_postgres_server",
    "ALL_POSTGRES_TOOLS",
    "DatabaseBackend",
    "PostgresBackend",
    "SQLiteTestBackend",
    "DatabaseConnectionError",
    "DatabaseQueryTimeoutError",
]


def __getattr__(name: str) -> Any:
    """Lazy import to prevent runpy RuntimeWarnings when executed as a module."""
    if name in ("PostgresMCPServer", "create_postgres_server", "ALL_POSTGRES_TOOLS"):
        from toolbridge.upstreams.postgres import server
        return getattr(server, name)
    elif name in (
        "DatabaseBackend",
        "PostgresBackend",
        "SQLiteTestBackend",
        "DatabaseConnectionError",
        "DatabaseQueryTimeoutError",
    ):
        from toolbridge.upstreams.postgres import backend
        return getattr(backend, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
