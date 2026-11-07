"""Audit logging service for persisting sanitized execution traces to SQLite."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Sequence
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from toolbridge.models.audit import AuditLogRecord
from toolbridge.security.sanitizer import SecretSanitizer

logger = logging.getLogger(__name__)


class AuditService:
    """Handles logging and querying of gateway execution events."""

    @staticmethod
    async def record_event(
        session: AsyncSession,
        caller_id: str,
        caller_role: str,
        tool_name: str,
        server_id: str,
        arguments: Any,
        status: str,
        duration_ms: float,
        response_summary: str = "",
    ) -> AuditLogRecord:
        """Create and persist an audit record with sanitized parameters."""
        sanitized_json = SecretSanitizer.to_sanitized_json(arguments)

        # Truncate summary if excessively large
        summary = str(response_summary)[:500]

        record = AuditLogRecord(
            timestamp=datetime.now(timezone.utc),
            caller_id=caller_id,
            caller_role=caller_role,
            tool_name=tool_name,
            server_id=server_id,
            arguments_json=sanitized_json,
            status=status,
            duration_ms=round(duration_ms, 2),
            response_summary=summary,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        logger.info(f"Audit log recorded #{record.id}: [{status}] '{tool_name}' by '{caller_id}' ({duration_ms:.1f}ms)")
        return record

    @staticmethod
    async def query_logs(
        session: AsyncSession,
        tool_name: str | None = None,
        status: str | None = None,
        caller_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[AuditLogRecord]:
        """Query audit logs with optional filtering and pagination."""
        stmt = select(AuditLogRecord).order_by(AuditLogRecord.timestamp.desc())

        if tool_name:
            stmt = stmt.where(AuditLogRecord.tool_name == tool_name)
        if status:
            stmt = stmt.where(AuditLogRecord.status == status)
        if caller_id:
            stmt = stmt.where(AuditLogRecord.caller_id == caller_id)

        stmt = stmt.limit(limit).offset(offset)
        result = await session.execute(stmt)
        return result.scalars().all()
