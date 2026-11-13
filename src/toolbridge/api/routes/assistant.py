"""API endpoints for ToolBridge Operational Assistant."""
from __future__ import annotations

import os
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from toolbridge.api.auth import AuthenticatedUser, require_role
from toolbridge.api.dependencies import get_assistant_service, get_rate_limiter
from toolbridge.assistant.service import AssistantService
from toolbridge.db.session import get_db_session
from toolbridge.models.assistant import (
    ActionExecutionRequest,
    ActionExecutionResponse,
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantStatusResponse,
    ProviderStatus,
)
from toolbridge.models.server import UserRole
from toolbridge.security.audit_service import AuditService
from toolbridge.security.rate_limiter import SlidingWindowRateLimiter

router = APIRouter(prefix="/api/v1/assistant", tags=["Assistant"])


@router.get("/status", response_model=AssistantStatusResponse)
async def get_assistant_status(
    assistant_service: Any = Depends(get_assistant_service),
    user: AuthenticatedUser = Depends(require_role(UserRole.READONLY)),
):
    """Retrieve operational status, model configuration, and connectivity of the assistant."""
    enabled = os.environ.get("TOOLBRIDGE_ASSISTANT_ENABLED", "false").lower() in ("true", "1", "yes")
    provider_name = getattr(assistant_service, "provider_name", "unconfigured") if assistant_service else "unconfigured"
    provider_status = getattr(assistant_service, "provider_status", ProviderStatus.UNCONFIGURED) if assistant_service else ProviderStatus.UNCONFIGURED
    model_name = os.environ.get("TOOLBRIDGE_ASSISTANT_MODEL", "gpt-4o-mini")
    rate_limit = int(os.environ.get("TOOLBRIDGE_ASSISTANT_RATE_LIMIT_PER_MINUTE", 15))
    timeout_sec = float(os.environ.get("TOOLBRIDGE_ASSISTANT_TIMEOUT_SECONDS", 8.0))

    return AssistantStatusResponse(
        enabled=enabled,
        status=provider_status,
        provider_name=provider_name,
        model_name=model_name,
        rate_limit_per_minute=rate_limit,
        timeout_seconds=timeout_sec,
    )


@router.post("/chat", response_model=AssistantChatResponse)
async def assistant_chat(
    payload: AssistantChatRequest,
    assistant_service: Any = Depends(get_assistant_service),
    rate_limiter: SlidingWindowRateLimiter = Depends(get_rate_limiter),
    db: AsyncSession = Depends(get_db_session),
    user: AuthenticatedUser = Depends(require_role(UserRole.OPERATOR)),
):
    """Submit an operational query to the assistant (Operator or Admin role required)."""
    if assistant_service is None or not isinstance(assistant_service, AssistantService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Assistant service is not initialized on this gateway instance.",
        )

    # 1. Dedicated Rate Limiting
    await rate_limiter.check_rate_limit(f"assistant:{user.caller_id}")

    # 2. Process Chat Query through Grounding Pipeline
    resp = await assistant_service.process_chat(
        query=payload.query,
        caller_role=user.role,
        caller_id=user.caller_id,
        include_recent_audit=payload.include_recent_audit,
        simulated_role=payload.simulated_role,
        db_session=db,
    )

    # 3. Record Audit Log Trace of Assistant Usage (Privacy-Preserving)
    summary = f"Q: {payload.query[:60]}... -> Answer length: {len(resp.answer)} chars ({resp.latency_ms}ms)"
    await AuditService.record_event(
        session=db,
        caller_id=user.caller_id,
        caller_role=user.role.value,
        tool_name="assistant__chat",
        server_id="gateway",
        arguments={"query_length": len(payload.query), "include_recent_audit": payload.include_recent_audit},
        status="SUCCESS",
        duration_ms=resp.latency_ms,
        response_summary=summary,
    )

    return resp


@router.post("/actions/execute", response_model=ActionExecutionResponse)
async def execute_proposed_action(
    payload: ActionExecutionRequest,
    assistant_service: Any = Depends(get_assistant_service),
    db: AsyncSession = Depends(get_db_session),
    user: AuthenticatedUser = Depends(require_role(UserRole.ADMIN)),
):
    """Execute a previously proposed action with explicit administrator confirmation (Admin only)."""
    if assistant_service is None or not isinstance(assistant_service, AssistantService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Assistant service is not initialized on this gateway instance.",
        )

    result = await assistant_service.execute_proposed_action(
        action_id=payload.action_id,
        caller=user,
        confirmed=payload.confirmed_by_admin,
        reason=payload.reason,
    )

    # Audit the human-confirmed execution
    exec_status = "SUCCESS" if result.success else "ERROR"
    await AuditService.record_event(
        session=db,
        caller_id=user.caller_id,
        caller_role=user.role.value,
        tool_name="assistant__execute_action",
        server_id="gateway",
        arguments={"action_id": payload.action_id, "confirmed": payload.confirmed_by_admin},
        status=exec_status,
        duration_ms=result.duration_ms,
        response_summary=str(result.result)[:200],
    )

    if not result.success:
        raise HTTPException(status_code=result.status_code, detail=str(result.result))

    return result
