"""FastAPI dependency injection providers."""
from __future__ import annotations

from typing import cast
from fastapi import Request

from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.router.dispatcher import ToolRouter
from toolbridge.security.rate_limiter import SlidingWindowRateLimiter


def get_registry(request: Request) -> ServerRegistry:
    """Retrieve shared ServerRegistry from FastAPI app state."""
    return cast(ServerRegistry, request.app.state.registry)


def get_client_manager(request: Request) -> MCPClientManager:
    """Retrieve shared MCPClientManager from FastAPI app state."""
    return cast(MCPClientManager, request.app.state.client_manager)


def get_router(request: Request) -> ToolRouter:
    """Retrieve shared ToolRouter from FastAPI app state."""
    return cast(ToolRouter, request.app.state.router)


def get_rate_limiter(request: Request) -> SlidingWindowRateLimiter:
    """Retrieve shared SlidingWindowRateLimiter from FastAPI app state."""
    return cast(SlidingWindowRateLimiter, request.app.state.rate_limiter)
