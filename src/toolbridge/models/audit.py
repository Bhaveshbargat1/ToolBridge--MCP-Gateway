"""Audit log SQLModel schema for recording all gateway invocations."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Index
from sqlmodel import Field, SQLModel


class AuditLogRecord(SQLModel, table=True):
    """Persistent audit record of an MCP tool invocation or API request."""
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_tool_timestamp", "tool_name", "timestamp"),
        Index("ix_audit_logs_status_timestamp", "status", "timestamp"),
        Index("ix_audit_logs_caller_timestamp", "caller_id", "timestamp"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    caller_id: str = Field(default="anonymous", index=True)
    caller_role: str = Field(default="anonymous")
    tool_name: str = Field(..., index=True)
    server_id: str = Field(..., index=True)
    arguments_json: str = Field(default="{}")
    status: str = Field(..., index=True)  # SUCCESS, ERROR, BLOCKED, RATE_LIMITED, UNAUTHORIZED
    duration_ms: float = Field(default=0.0)
    response_summary: str = Field(default="")
