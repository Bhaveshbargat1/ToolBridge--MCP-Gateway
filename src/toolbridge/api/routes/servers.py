"""Upstream Server Management endpoints."""
from __future__ import annotations

import os
import re
import sys
from typing import Final
from fastapi import APIRouter, Depends, HTTPException, status

from toolbridge.api.auth import AuthenticatedUser, require_role
from toolbridge.api.dependencies import get_client_manager, get_registry
from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import UpstreamServerConfig, UserRole

router = APIRouter(prefix="/api/v1/servers", tags=["Servers"])

PRECONFIGURED_SERVERS: Final[set[str]] = {"filesystem", "postgres", "github"}
SHELL_METACHARS: Final[set[str]] = {"&", "|", ";", "$", ">", "<", "`", "\n", "\r"}
DISALLOWED_EVAL_FLAGS: Final[set[str]] = {"-c", "-e", "--eval", "/c", "-r"}


def is_dynamic_servers_allowed() -> bool:
    """Check if dynamic upstream server registration is enabled via environment."""
    return os.environ.get("TOOLBRIDGE_ALLOW_DYNAMIC_SERVERS", "false").strip().lower() in ("true", "1", "yes")


def get_allowed_commands() -> set[str]:
    """Retrieve allowlist of executable paths permitted for upstream servers."""
    env_allowed = os.environ.get("TOOLBRIDGE_ALLOWED_COMMANDS", "")
    if env_allowed.strip():
        return {os.path.abspath(c.strip()) for c in env_allowed.split(",") if c.strip()}
    return {os.path.abspath(sys.executable)}


def validate_server_config(config: UpstreamServerConfig) -> None:
    """Validate server configuration against command injection, shell metacharacters, and bad identifiers."""
    # B6e: Forbid '__' in server ID and validate identifier
    if "__" in config.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Server ID '{config.id}' cannot contain double underscores ('__').",
        )
    if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", config.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Server ID '{config.id}' must match pattern ^[a-zA-Z0-9_-]{{1,64}}$.",
        )

    # Command and arguments validation
    if config.command:
        # Check shell metacharacters in command
        if any(ch in config.command for ch in SHELL_METACHARS):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Command contains disallowed shell metacharacters.",
            )

        # Check allowed commands whitelist
        cmd_path = os.path.abspath(config.command)
        allowed = get_allowed_commands()
        if cmd_path not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Command '{config.command}' is not in the allowed commands whitelist.",
            )

    for arg in config.args:
        if any(ch in arg for ch in SHELL_METACHARS):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Argument '{arg}' contains disallowed shell metacharacters.",
            )
        arg_lower = arg.strip().lower()
        if arg_lower in DISALLOWED_EVAL_FLAGS or any(arg_lower.startswith(f + "=") for f in DISALLOWED_EVAL_FLAGS):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Disallowed interpreter evaluation flag '{arg}' in arguments.",
            )


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
    if not is_dynamic_servers_allowed():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dynamic server registration is disabled by policy (TOOLBRIDGE_ALLOW_DYNAMIC_SERVERS=false).",
        )

    validate_server_config(config)

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
    if not is_dynamic_servers_allowed() and server_id not in PRECONFIGURED_SERVERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dynamic server unregistration is disabled by policy.",
        )

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
    if not is_dynamic_servers_allowed() and server_id not in PRECONFIGURED_SERVERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Dynamic operations on non-preconfigured server '{server_id}' are disabled.",
        )

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
    if not is_dynamic_servers_allowed() and server_id not in PRECONFIGURED_SERVERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Dynamic operations on non-preconfigured server '{server_id}' are disabled.",
        )

    await client_manager.disconnect_server(server_id)
    return {"message": f"Server '{server_id}' disconnected."}
