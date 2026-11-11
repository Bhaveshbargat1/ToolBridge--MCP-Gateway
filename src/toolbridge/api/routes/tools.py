"""Tool Catalog and Invocation endpoints."""
from __future__ import annotations

import time
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from toolbridge.api.auth import AuthenticatedUser, require_role
from toolbridge.api.dependencies import get_rate_limiter, get_registry, get_router
from toolbridge.db.session import get_db_session
from toolbridge.router.dispatcher import ToolRouter
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import UserRole
from toolbridge.security.audit_service import AuditService
from toolbridge.security.policy import PolicyEngine, SensitivityTier
from toolbridge.security.rate_limiter import SlidingWindowRateLimiter

router = APIRouter(prefix="/api/v1/tools", tags=["Tools"])


class ToolInvocationRequest(BaseModel):
    """Payload for invoking an MCP tool through the Management API."""
    tool_name: str = Field(..., description="Namespaced tool name (e.g. 'filesystem__read_file')")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Input arguments for tool")


@router.get("")
async def list_tools(
    registry: ServerRegistry = Depends(get_registry),
    user: AuthenticatedUser = Depends(require_role(UserRole.READONLY)),
):
    """List all exposed tools across connected servers with sensitivity classifications."""
    tools = await registry.get_all_tools()
    items = []
    for t in tools:
        tier = PolicyEngine.get_tool_sensitivity(t.namespaced_name)
        items.append({
            "namespaced_name": t.namespaced_name,
            "original_name": t.original_name,
            "server_id": t.server_id,
            "description": t.description,
            "sensitivity_tier": tier.value,
            "input_schema": t.input_schema,
        })
    return {"total": len(items), "tools": items}


@router.post("/invoke")
async def invoke_tool(
    request: ToolInvocationRequest,
    router_proxy: ToolRouter = Depends(get_router),
    registry: ServerRegistry = Depends(get_registry),
    rate_limiter: SlidingWindowRateLimiter = Depends(get_rate_limiter),
    db: AsyncSession = Depends(get_db_session),
    user: AuthenticatedUser = Depends(require_role(UserRole.READONLY)),
):
    """Execute a tool with rate limiting, role-based authorization, and audit logging."""
    tool_name = request.tool_name
    args = request.arguments

    # 1. Rate Limiting Check
    await rate_limiter.check_rate_limit(user.caller_id)

    # 2. Tool Existence Verification
    tool = await registry.get_tool(tool_name)
    if not tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_name}' not found.",
        )

    # 3. User & Tool-Level Authorization Check
    is_authorized, reason = PolicyEngine.is_authorized(user.role, tool_name)
    if not is_authorized:
        # Record unauthorized attempt in audit log
        await AuditService.record_event(
            session=db,
            caller_id=user.caller_id,
            caller_role=user.role.value,
            tool_name=tool_name,
            server_id=tool.server_id,
            arguments=args,
            status="UNAUTHORIZED",
            duration_ms=0.0,
            response_summary=reason,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)

    # 4. Tool Execution & Timing
    start_time = time.perf_counter()
    result = await router_proxy.dispatch(tool_name, args, tool=tool)
    duration_ms = (time.perf_counter() - start_time) * 1000

    # 5. Determine Result Status & Summary
    exec_status = "ERROR" if result.is_error else "SUCCESS"
    summary_text = result.content[0].text if result.content else ""

    # 6. Record Audit Log
    await AuditService.record_event(
        session=db,
        caller_id=user.caller_id,
        caller_role=user.role.value,
        tool_name=tool_name,
        server_id=tool.server_id,
        arguments=args,
        status=exec_status,
        duration_ms=duration_ms,
        response_summary=summary_text,
    )

    if result.is_error:
        # Return 400 Bad Request for execution/schema failures
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=summary_text,
        )

    return {
        "status": "success",
        "tool_name": tool_name,
        "duration_ms": round(duration_ms, 2),
        "result": summary_text,
    }
