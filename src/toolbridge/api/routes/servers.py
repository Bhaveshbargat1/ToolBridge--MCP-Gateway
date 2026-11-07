"""Upstream Server Management endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from toolbridge.api.auth import AuthenticatedUser, require_role
from toolbridge.api.dependencies import get_client_manager, get_registry
from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import UpstreamServerConfig, UserRole

router = APIRouter(prefix="/api/v1/servers", tags=["Servers"])


@router.get("")
async def list_servers(
    registry: ServerRegistry = Depends(get_registry),
    user: AuthenticatedUser = Depends(require_role(UserRole.READONLY)),
):
    """List all registered upstream servers and their runtime statuses."""
    servers = await registry.get_all_servers()
    return {"total": len(servers), "servers": servers}


@router.post("", status_code=status.HTTP_201_CREATED)
async def register_server(
    config: UpstreamServerConfig,
    registry: ServerRegistry = Depends(get_registry),
    user: AuthenticatedUser = Depends(require_role(UserRole.ADMIN)),
):
    """Register a new upstream MCP server configuration (Admin only)."""
    existing = await registry.get_server(config.id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Server with ID '{config.id}' already exists.",
        )
    server_info = await registry.register_server(config)
    return {"message": "Server registered successfully", "server": server_info}


@router.delete("/{server_id}")
async def unregister_server(
    server_id: str,
    registry: ServerRegistry = Depends(get_registry),
    client_manager: MCPClientManager = Depends(get_client_manager),
    user: AuthenticatedUser = Depends(require_role(UserRole.ADMIN)),
):
    """Disconnect and unregister an upstream server (Admin only)."""
    await client_manager.disconnect_server(server_id)
    removed = await registry.unregister_server(server_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Server '{server_id}' not found.",
        )
    return {"message": f"Server '{server_id}' unregistered successfully."}


@router.post("/{server_id}/connect")
async def connect_server(
    server_id: str,
    client_manager: MCPClientManager = Depends(get_client_manager),
    user: AuthenticatedUser = Depends(require_role(UserRole.OPERATOR)),
):
    """Manually initiate an MCP connection to an upstream server."""
    success = await client_manager.connect_server(server_id)
    if not success:
        server_info = await client_manager.registry.get_server(server_id)
        err = server_info.last_error if server_info else "Connection failed"
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to server '{server_id}': {err}",
        )
    return {"message": f"Successfully connected to '{server_id}'."}


@router.post("/{server_id}/disconnect")
async def disconnect_server(
    server_id: str,
    client_manager: MCPClientManager = Depends(get_client_manager),
    user: AuthenticatedUser = Depends(require_role(UserRole.OPERATOR)),
):
    """Disconnect an active upstream server."""
    await client_manager.disconnect_server(server_id)
    return {"message": f"Server '{server_id}' disconnected."}
