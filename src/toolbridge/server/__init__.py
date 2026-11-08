"""ToolBridge Server package."""
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from toolbridge.server.gateway import (
        ToolBridgeGatewayServer,
        run_gateway_stdio,
        main,
    )

__all__ = [
    "ToolBridgeGatewayServer",
    "run_gateway_stdio",
    "main",
]


def __getattr__(name: str) -> Any:
    """Lazy import to prevent runpy RuntimeWarnings when executed as a module."""
    if name in __all__:
        from toolbridge.server import gateway
        return getattr(gateway, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
