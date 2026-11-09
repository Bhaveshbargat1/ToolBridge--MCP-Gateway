"""Unit tests for SQLite database session pragmas."""
from pathlib import Path
import pytest
from sqlalchemy import text
from toolbridge.db.session import get_engine, get_session


@pytest.mark.unit
@pytest.mark.asyncio
async def test_sqlite_pragmas_wal_and_busy_timeout(tmp_path: Path):
    """Verify that SQLite connections are initialized with WAL mode and busy_timeout=5000."""
    db_file = tmp_path / "test_pragmas.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    engine = get_engine(db_url)

    async with get_session(engine) as session:
        # Check journal mode (WAL)
        res = await session.execute(text("PRAGMA journal_mode;"))
        mode = res.scalar()
        assert mode.lower() == "wal"

        # Check busy timeout (5000ms)
        timeout_res = await session.execute(text("PRAGMA busy_timeout;"))
        timeout = timeout_res.scalar()
        assert timeout == 5000
