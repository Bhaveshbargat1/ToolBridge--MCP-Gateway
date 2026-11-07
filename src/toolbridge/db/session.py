"""SQLite asynchronous database engine and session management for ToolBridge."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

_DEFAULT_DB_URL = "sqlite+aiosqlite:///./data/toolbridge.db"
_engine: AsyncEngine | None = None


def get_engine(db_url: str | None = None) -> AsyncEngine:
    """Retrieve or create the global async database engine."""
    global _engine
    if _engine is None:
        url = db_url or os.environ.get("TOOLBRIDGE_SQLITE_URL", _DEFAULT_DB_URL)
        # Ensure parent directory exists for file-based sqlite
        if "sqlite" in url and ":///" in url and not url.endswith(":memory:"):
            db_file_path = url.split(":///", 1)[1]
            os.makedirs(os.path.dirname(os.path.abspath(db_file_path)), exist_ok=True)

        _engine = create_async_engine(
            url,
            echo=False,
            future=True,
            connect_args={"check_same_thread": False} if "sqlite" in url else {},
        )
    return _engine


async def init_db(engine: AsyncEngine | None = None) -> None:
    """Initialize all database tables asynchronously."""
    eng = engine or get_engine()
    async with eng.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


@asynccontextmanager
async def get_session(engine: AsyncEngine | None = None) -> AsyncGenerator[AsyncSession, None]:
    """Provide an asynchronous database session context."""
    eng = engine or get_engine()
    async_session_factory = sessionmaker(
        eng,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for yielding database sessions."""
    async with get_session() as session:
        yield session
