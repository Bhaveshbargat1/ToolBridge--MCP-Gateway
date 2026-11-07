"""Database backend adapters for PostgreSQL and hermetic testing."""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Mapping, Sequence
import aiosqlite
import asyncpg


class DatabaseConnectionError(ConnectionError):
    """Raised when connecting to the database fails."""
    pass


class DatabaseQueryTimeoutError(TimeoutError):
    """Raised when an SQL query exceeds execution timeout."""
    pass


class DatabaseBackend(ABC):
    """Abstract interface for database query and metadata operations."""

    @abstractmethod
    async def connect(self) -> None:
        """Initialize database connection or pool."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close database connection or pool."""
        pass

    @abstractmethod
    async def list_tables(self, schema: str = "public") -> list[dict[str, Any]]:
        """List tables and views in the designated schema."""
        pass

    @abstractmethod
    async def describe_table(self, table_name: str, schema: str = "public") -> list[dict[str, Any]]:
        """Retrieve schema columns and data types for a table."""
        pass

    @abstractmethod
    async def execute_query(
        self,
        query: str,
        parameters: Sequence[Any] | None = None,
        timeout_seconds: float = 10.0,
        max_rows: int = 500,
    ) -> list[dict[str, Any]]:
        """Execute a read-only query with parameters and timeout."""
        pass


class PostgresBackend(DatabaseBackend):
    """Production PostgreSQL backend using asyncpg with read-only connection pooling."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "toolbridge_demo",
        user: str = "mcp_readonly",
        password: str = "",
        min_pool_size: int = 1,
        max_pool_size: int = 10,
        connect_timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.min_pool_size = min_pool_size
        self.max_pool_size = max_pool_size
        self.connect_timeout = connect_timeout
        self._pool: asyncpg.Pool | None = None

    async def _init_connection(self, conn: asyncpg.Connection) -> None:
        """Database-level defense-in-depth: enforce transaction read-only mode."""
        await conn.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;")
        await conn.execute("SET statement_timeout = 15000;")  # 15s server-level timeout

    async def connect(self) -> None:
        """Create asyncpg connection pool with connection initialization hooks."""
        if self._pool is not None:
            return

        try:
            self._pool = await asyncio.wait_for(
                asyncpg.create_pool(
                    host=self.host,
                    port=self.port,
                    database=self.database,
                    user=self.user,
                    password=self.password,
                    min_size=self.min_pool_size,
                    max_size=self.max_pool_size,
                    init=self._init_connection,
                ),
                timeout=self.connect_timeout,
            )
        except (OSError, asyncpg.PostgresError, asyncio.TimeoutError) as e:
            raise DatabaseConnectionError(
                f"Failed to connect to PostgreSQL at {self.host}:{self.port}/{self.database}: {e}"
            ) from e

    async def disconnect(self) -> None:
        """Close connection pool."""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def list_tables(self, schema: str = "public") -> list[dict[str, Any]]:
        """List tables from information_schema."""
        await self.connect()
        sql = """
            SELECT table_name, table_type
            FROM information_schema.tables
            WHERE table_schema = $1
            ORDER BY table_name;
        """
        async with self._pool.acquire() as conn:
            records = await conn.fetch(sql, schema)
            return [dict(r) for r in records]

    async def describe_table(self, table_name: str, schema: str = "public") -> list[dict[str, Any]]:
        """Retrieve column names, data types, nullability, and defaults."""
        await self.connect()
        sql = """
            SELECT 
                column_name, 
                data_type, 
                is_nullable, 
                column_default
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2
            ORDER BY ordinal_position;
        """
        async with self._pool.acquire() as conn:
            records = await conn.fetch(sql, schema, table_name)
            if not records:
                raise FileNotFoundError(f"Table '{table_name}' not found in schema '{schema}'.")
            return [dict(r) for r in records]

    async def execute_query(
        self,
        query: str,
        parameters: Sequence[Any] | None = None,
        timeout_seconds: float = 10.0,
        max_rows: int = 500,
    ) -> list[dict[str, Any]]:
        """Execute parameterized query safely with statement timeout."""
        await self.connect()
        params = list(parameters or [])

        async with self._pool.acquire() as conn:
            try:
                records = await asyncio.wait_for(
                    conn.fetch(query, *params),
                    timeout=timeout_seconds,
                )
            except asyncio.TimeoutError:
                raise DatabaseQueryTimeoutError(
                    f"Query execution timed out after {timeout_seconds} seconds."
                )
            except asyncpg.PostgresError as e:
                raise RuntimeError(f"PostgreSQL Execution Error: {e}") from e

            # Limit rows
            limited = records[:max_rows]
            return [dict(r) for r in limited]


class SQLiteTestBackend(DatabaseBackend):
    """Hermetic SQLite test adapter pre-populated with sample data for offline verification."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        if self._conn is not None:
            return

        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row

        # Setup sample tables for testing
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER,
                amount REAL NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY (customer_id) REFERENCES customers (id)
            );
        """)

        # Insert seed data if table is empty
        cursor = await self._conn.execute("SELECT count(*) as count FROM customers")
        row = await cursor.fetchone()
        if row["count"] == 0:
            await self._conn.execute(
                "INSERT INTO customers (id, name, email) VALUES (1, 'Alice Smith', 'alice@example.com')"
            )
            await self._conn.execute(
                "INSERT INTO customers (id, name, email) VALUES (2, 'Bob Jones', 'bob@example.com')"
            )
            await self._conn.execute(
                "INSERT INTO orders (id, customer_id, amount, status) VALUES (101, 1, 150.50, 'completed')"
            )
            await self._conn.execute(
                "INSERT INTO orders (id, customer_id, amount, status) VALUES (102, 1, 45.00, 'pending')"
            )
            await self._conn.commit()

        # Enforce read-only at database connection level
        await self._conn.execute("PRAGMA query_only = ON;")

    async def disconnect(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def list_tables(self, schema: str = "public") -> list[dict[str, Any]]:
        await self.connect()
        sql = "SELECT name as table_name, type as table_type FROM sqlite_master WHERE type in ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name"
        cursor = await self._conn.execute(sql)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def describe_table(self, table_name: str, schema: str = "public") -> list[dict[str, Any]]:
        await self.connect()
        cursor = await self._conn.execute(f"PRAGMA table_info({table_name});")
        rows = await cursor.fetchall()
        if not rows:
            raise FileNotFoundError(f"Table '{table_name}' does not exist.")
        columns = []
        for r in rows:
            columns.append({
                "column_name": r["name"],
                "data_type": r["type"],
                "is_nullable": "YES" if not r["notnull"] else "NO",
                "column_default": r["dflt_value"],
                "is_primary_key": bool(r["pk"]),
            })
        return columns

    async def execute_query(
        self,
        query: str,
        parameters: Sequence[Any] | None = None,
        timeout_seconds: float = 10.0,
        max_rows: int = 500,
    ) -> list[dict[str, Any]]:
        await self.connect()
        params = list(parameters or [])
        # Translate Postgres parameter placeholders ($1, $2) to SQLite (?) for test backend
        import re
        sqlite_query = re.sub(r"\$\d+", "?", query)

        try:
            cursor = await asyncio.wait_for(
                self._conn.execute(sqlite_query, params),
                timeout=timeout_seconds,
            )
            rows = await cursor.fetchmany(max_rows)
            return [dict(r) for r in rows]
        except asyncio.TimeoutError:
            raise DatabaseQueryTimeoutError(f"Query timed out after {timeout_seconds} seconds.")
        except Exception as e:
            raise RuntimeError(f"Database Execution Error: {e}") from e
