"""Health check endpoint."""
from __future__ import annotations

import time
from fastapi import APIRouter, Depends
from toolbridge.api.dependencies import get_client_manager, get_registry
from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import ServerStatus

router = APIRouter(tags=["Health"])
_BOOT_TIME = time.time()


@router.get("/health")
async def health_check(
    registry: ServerRegistry = Depends(get_registry),
    client_manager: MCPClientManager = Depends(get_client_manager),
):
    """Retrieve gateway operational health, uptime, and active upstream metrics."""
    servers = await registry.get_all_servers()
    connected_count = sum(1 for s in servers if s.status == ServerStatus.CONNECTED)
    tools = await registry.get_all_tools()

    return {
        "status": "healthy",
        "gateway": "ToolBridge Enterprise MCP Gateway",
        "version": "0.1.0",
        "uptime_seconds": round(time.time() - _BOOT_TIME, 1),
        "total_servers": len(servers),
        "connected_servers": connected_count,
        "total_tools": len(tools),
    }
