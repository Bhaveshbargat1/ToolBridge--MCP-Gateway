"""FastAPI Application factory for ToolBridge Management Service."""
from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

from toolbridge.api.routes import assistant, audit, health, servers, tools
from toolbridge.assistant.service import AssistantService
from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.db.session import init_db
from toolbridge.models.server import TransportType, UpstreamServerConfig
from toolbridge.router.dispatcher import ToolRouter
from toolbridge.security.guards.filesystem import resolve_sandbox_root
from toolbridge.security.rate_limiter import RateLimitExceededError, SlidingWindowRateLimiter

logger = logging.getLogger("toolbridge.api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle."""
    # 0. Enforce API key configuration at startup - fail fast if missing or insecure
    from toolbridge.api.auth import get_configured_api_keys
    get_configured_api_keys()

    logger.info("Initializing ToolBridge Management Service & Database...")
    await init_db()

    # If registry is empty, configure defaults
    registry: ServerRegistry = app.state.registry
    manager: MCPClientManager = app.state.client_manager

    servers = await registry.get_all_servers()
    if not servers:
        fs_sandbox = str(resolve_sandbox_root())
        await registry.register_server(UpstreamServerConfig(
            id="filesystem",
            name="Sandboxed Filesystem Server",
            transport=TransportType.STDIO,
            command=sys.executable,
            args=["-m", "toolbridge.upstreams.filesystem.server"],
            env={"FILESYSTEM_SANDBOX_ROOT": fs_sandbox},
        ))
        await registry.register_server(UpstreamServerConfig(
            id="postgres",
            name="PostgreSQL Server",
            transport=TransportType.STDIO,
            command=sys.executable,
            args=["-m", "toolbridge.upstreams.postgres.server"],
        ))
        await registry.register_server(UpstreamServerConfig(
            id="github",
            name="GitHub Server",
            transport=TransportType.STDIO,
            command=sys.executable,
            args=["-m", "toolbridge.upstreams.github.server"],
            env={"GITHUB_PERSONAL_ACCESS_TOKEN": os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", "")},
        ))

    logger.info("Booting upstream MCP server connections...")
    try:
        await manager.connect_all()
    except Exception as e:
        logger.warning(f"Initial upstream connect_all warning: {e}")

    yield

    logger.info("Shutting down ToolBridge Management Service...")
    await manager.disconnect_all()


def create_app(
    registry: ServerRegistry | None = None,
    client_manager: MCPClientManager | None = None,
    rate_limiter: SlidingWindowRateLimiter | None = None,
) -> FastAPI:
    """Create and configure the FastAPI Management application."""
    reg = registry or ServerRegistry()
    mgr = client_manager or MCPClientManager(registry=reg)
    rt = ToolRouter(client_manager=mgr, registry=reg)
    limiter = rate_limiter or SlidingWindowRateLimiter(max_requests_per_minute=60)

    app = FastAPI(
        title="ToolBridge Management API",
        version="0.1.0",
        description="Enterprise MCP Gateway Management and Audit API",
        lifespan=lifespan,
    )

    # Store shared singletons on app state
    asst_service = AssistantService(registry=reg, router=rt, client_manager=mgr)
    app.state.registry = reg
    app.state.client_manager = mgr
    app.state.router = rt
    app.state.rate_limiter = limiter
    app.state.assistant_service = asst_service

    # Exception Handlers
    @app.exception_handler(RateLimitExceededError)
    async def rate_limit_handler(request: Request, exc: RateLimitExceededError):
        return JSONResponse(
            status_code=429,
            content={"detail": str(exc), "retry_after_seconds": exc.retry_after},
            headers={"Retry-After": str(int(exc.retry_after))},
        )

    # Include API Routers
    app.include_router(health.router)
    app.include_router(servers.router)
    app.include_router(tools.router)
    app.include_router(audit.router)
    app.include_router(assistant.router)

    # Mount Static Web App Frontend
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(static_dir):
        from fastapi.responses import HTMLResponse
        from fastapi.staticfiles import StaticFiles

        app.mount("/static", StaticFiles(directory=static_dir), name="static")

        index_path = os.path.join(static_dir, "index.html")
        cached_index_html: str | None = None
        if os.path.exists(index_path):
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    cached_index_html = f.read()
            except Exception:
                cached_index_html = None

        @app.get("/", include_in_schema=False, response_class=HTMLResponse)
        async def serve_index():
            content = cached_index_html
            if content is None:
                try:
                    with open(index_path, "r", encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    return HTMLResponse(content="<h1>ToolBridge Web Control Center</h1>", status_code=200)

            # Inject active keys for local web console session
            admin_k = os.environ.get("TOOLBRIDGE_ADMIN_KEY", "")
            oper_k = os.environ.get("TOOLBRIDGE_OPERATOR_KEY", "")
            ro_k = os.environ.get("TOOLBRIDGE_READONLY_KEY", "")
            dev_script = (
                f'<script id="tb-env-keys">\n'
                f'  window.__TOOLBRIDGE_DEV_KEYS__ = {{\n'
                f'    admin: "{admin_k}",\n'
                f'    operator: "{oper_k}",\n'
                f'    readonly: "{ro_k}"\n'
                f'  }};\n'
                f'</script>\n'
            )
            if "</head>" in content:
                content = content.replace("</head>", f"{dev_script}</head>", 1)
            else:
                content = dev_script + content

            return HTMLResponse(content=content, media_type="text/html")

    return app


app = create_app()


def main() -> None:
    """Run the management API server."""
    host = os.environ.get("TOOLBRIDGE_API_HOST", "127.0.0.1")
    port = int(os.environ.get("TOOLBRIDGE_API_PORT", 8000))
    uvicorn.run("toolbridge.api.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
