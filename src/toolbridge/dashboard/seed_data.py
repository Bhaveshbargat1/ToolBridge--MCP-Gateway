"""Seed realistic demo audit records for ToolBridge Streamlit Dashboard."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import random

from sqlmodel import select
from toolbridge.db.session import get_engine, get_session, init_db
from toolbridge.models.audit import AuditLogRecord
from toolbridge.security.sanitizer import SecretSanitizer


async def seed_audit_logs(count: int = 25, force: bool = False) -> int:
    """Seed sample audit log records into SQLite database if empty or force=True."""
    await init_db()

    async with get_session() as session:
        # Check existing
        stmt = select(AuditLogRecord)
        result = await session.execute(stmt)
        existing = result.scalars().all()
        if existing and not force:
            return len(existing)

        now = datetime.now(timezone.utc)
        sample_scenarios = [
            # 1. Successful filesystem read
            {
                "caller_id": "agent-claude-01",
                "caller_role": "operator",
                "tool_name": "filesystem__read_file",
                "server_id": "filesystem",
                "args": {"path": "docs/architecture.md", "encoding": "utf-8"},
                "status": "SUCCESS",
                "duration_ms": 3.8,
                "summary": "File read successfully (1,420 bytes).",
                "minutes_ago": 45,
            },
            # 2. Path traversal attack attempt blocked by FilesystemGuard
            {
                "caller_id": "untrusted-agent-99",
                "caller_role": "readonly",
                "tool_name": "filesystem__read_file",
                "server_id": "filesystem",
                "args": {"path": "../../windows/system32/cmd.exe"},
                "status": "ERROR",
                "duration_ms": 1.2,
                "summary": "PathSecurityError: Traversal attempt blocked: path escapes designated workspace.",
                "minutes_ago": 40,
            },
            # 3. Successful Postgres query
            {
                "caller_id": "analyst-dashboard",
                "caller_role": "readonly",
                "tool_name": "postgres__execute_query",
                "server_id": "postgres",
                "args": {"query": "SELECT id, username, email FROM users LIMIT 10;", "params": []},
                "status": "SUCCESS",
                "duration_ms": 14.5,
                "summary": "Returned 10 rows in 0.015s.",
                "minutes_ago": 35,
            },
            # 4. SQL Injection attempt blocked by SQLSecurityGuard AST inspector
            {
                "caller_id": "rogue-agent-07",
                "caller_role": "readonly",
                "tool_name": "postgres__execute_query",
                "server_id": "postgres",
                "args": {"query": "SELECT * FROM users; DROP TABLE audit_logs; --"},
                "status": "ERROR",
                "duration_ms": 2.1,
                "summary": "SQLSecurityError: Multiple SQL statements detected. Only single statements permitted.",
                "minutes_ago": 30,
            },
            # 5. DDL command rejected
            {
                "caller_id": "analyst-dashboard",
                "caller_role": "readonly",
                "tool_name": "postgres__execute_query",
                "server_id": "postgres",
                "args": {"query": "ALTER TABLE orders ADD COLUMN test INT;"},
                "status": "ERROR",
                "duration_ms": 1.9,
                "summary": "SQLSecurityError: Forbidden SQL statement type: ALTER.",
                "minutes_ago": 25,
            },
            # 6. GitHub repository search
            {
                "caller_id": "developer-sarah",
                "caller_role": "operator",
                "tool_name": "github__search_repositories",
                "server_id": "github",
                "args": {"query": "modelcontextprotocol python", "token": "ghp_secretTokenMasked1234567890abcdef"},
                "status": "SUCCESS",
                "duration_ms": 128.4,
                "summary": "Found 3 matching repositories.",
                "minutes_ago": 20,
            },
            # 7. Sensitive write rejected due to insufficient role
            {
                "caller_id": "guest-guest",
                "caller_role": "readonly",
                "tool_name": "filesystem__write_file",
                "server_id": "filesystem",
                "args": {"path": "config/settings.json", "content": "{\"debug\": true}"},
                "status": "UNAUTHORIZED",
                "duration_ms": 0.5,
                "summary": "Role 'readonly' is not permitted to execute sensitive tool 'filesystem__write_file'.",
                "minutes_ago": 18,
            },
            # 8. Sensitive write succeeded with admin
            {
                "caller_id": "admin-system",
                "caller_role": "admin",
                "tool_name": "filesystem__write_file",
                "server_id": "filesystem",
                "args": {"path": "logs/summary.txt", "content": "Daily maintenance complete.", "overwrite": True},
                "status": "SUCCESS",
                "duration_ms": 7.2,
                "summary": "Wrote 28 bytes atomically to logs/summary.txt.",
                "minutes_ago": 15,
            },
            # 9. Rate limit exceeded
            {
                "caller_id": "spammer-bot",
                "caller_role": "readonly",
                "tool_name": "postgres__list_tables",
                "server_id": "postgres",
                "args": {},
                "status": "RATE_LIMITED",
                "duration_ms": 0.2,
                "summary": "Rate limit exceeded (60 requests/min). Retry after 38.2s.",
                "minutes_ago": 10,
            },
            # 10. List directory
            {
                "caller_id": "agent-claude-01",
                "caller_role": "operator",
                "tool_name": "filesystem__list_directory",
                "server_id": "filesystem",
                "args": {"path": "src", "recursive": False},
                "status": "SUCCESS",
                "duration_ms": 4.1,
                "summary": "Listed 6 items in directory 'src'.",
                "minutes_ago": 5,
            },
            # 11. GitHub issues list
            {
                "caller_id": "product-bot",
                "caller_role": "readonly",
                "tool_name": "github__list_issues",
                "server_id": "github",
                "args": {"owner": "modelcontextprotocol", "repo": "python-sdk", "state": "open"},
                "status": "SUCCESS",
                "duration_ms": 89.6,
                "summary": "Retrieved 15 open issues.",
                "minutes_ago": 2,
            },
            # 12. PostgreSQL describe table
            {
                "caller_id": "analyst-dashboard",
                "caller_role": "readonly",
                "tool_name": "postgres__describe_table",
                "server_id": "postgres",
                "args": {"table_name": "users"},
                "status": "SUCCESS",
                "duration_ms": 11.3,
                "summary": "Table 'users' has 5 columns (id, username, email, created_at, role).",
                "minutes_ago": 1,
            },
        ]

        inserted = 0
        for item in sample_scenarios:
            record_time = now - timedelta(minutes=item["minutes_ago"])
            sanitized_args = SecretSanitizer.to_sanitized_json(item["args"])
            record = AuditLogRecord(
                timestamp=record_time,
                caller_id=item["caller_id"],
                caller_role=item["caller_role"],
                tool_name=item["tool_name"],
                server_id=item["server_id"],
                arguments_json=sanitized_args,
                status=item["status"],
                duration_ms=item["duration_ms"],
                response_summary=item["summary"],
            )
            session.add(record)
            inserted += 1

        await session.commit()
        return inserted


if __name__ == "__main__":
    count = asyncio.run(seed_audit_logs(force=True))
    print(f"Seeded {count} demo audit records into SQLite.")
