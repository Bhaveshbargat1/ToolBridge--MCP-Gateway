"""Audit Log Inspection endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from toolbridge.api.auth import AuthenticatedUser, require_role
from toolbridge.db.session import get_db_session
from toolbridge.models.audit import AuditLogRecord
from toolbridge.models.server import UserRole
from toolbridge.security.audit_service import AuditService

router = APIRouter(prefix="/api/v1/audit", tags=["Audit"])


@router.get("")
async def query_audit_logs(
    tool_name: str | None = Query(default=None, description="Filter by tool name"),
    status: str | None = Query(default=None, description="Filter by status (SUCCESS, ERROR, UNAUTHORIZED)"),
    caller_id: str | None = Query(default=None, description="Filter by caller ID"),
    limit: int = Query(default=50, ge=1, le=200, description="Max logs to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    db: AsyncSession = Depends(get_db_session),
    user: AuthenticatedUser = Depends(require_role(UserRole.ADMIN)),
):
    """Search and inspect sanitized execution audit logs (Operator or Admin only)."""
    logs = await AuditService.query_logs(
        session=db,
        tool_name=tool_name,
        status=status,
        caller_id=caller_id,
        limit=limit,
        offset=offset,
    )
    return {
        "count": len(logs),
        "limit": limit,
        "offset": offset,
        "logs": logs,
    }


@router.post("/seed")
async def seed_audit_records():
    """Seed realistic execution and security traces into SQLite."""
    from toolbridge.dashboard.seed_data import seed_audit_logs
    count = await seed_audit_logs(force=True)
    return {"message": f"Successfully seeded {count} audit records into SQLite.", "count": count}


@router.get("/{log_id}")
async def get_audit_log_by_id(
    log_id: int,
    db: AsyncSession = Depends(get_db_session),
    user: AuthenticatedUser = Depends(require_role(UserRole.ADMIN)),
):
    """Retrieve a single audit log entry by ID."""
    stmt = select(AuditLogRecord).where(AuditLogRecord.id == log_id)
    result = await db.execute(stmt)
    record = result.scalar_one_or_none()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit log #{log_id} not found.",
        )
    return record
