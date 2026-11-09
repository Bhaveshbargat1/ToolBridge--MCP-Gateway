"""Database backend adapters for PostgreSQL and hermetic testing."""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
import logging
import os
import re
import sys
from typing import Any, Mapping, Sequence
import aiosqlite
import asyncpg

logger = logging.getLogger("toolbridge.postgres.backend")


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
        host: str = "127.0.0.1",
        port: int = 5432,
        database: str = "toolbridge_demo",
        user: str = "mcp_readonly",
        password: str = "",
        min_pool_size: int = 1,
        max_pool_size: int = 10,
        connect_timeout: float = 2.0,
    ) -> None:
        self.host = "127.0.0.1" if host == "localhost" else host
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
        await conn.execute("SET statement_timeout = 10000;")  # 10s server-level timeout

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
                async with conn.transaction(readonly=True):
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
            finally:
                try:
                    await conn.execute("DISCARD ALL;")
                except Exception:
                    pass

            limited = records[:max_rows]
            return [dict(r) for r in limited]


class SQLiteTestBackend(DatabaseBackend):
    """Hermetic SQLite adapter pre-populated with sample schema and data."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        if self._conn is not None:
            return

        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row

        # Setup sample tables for testing and offline execution
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                company TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER,
                total_amount REAL NOT NULL,
                status TEXT NOT NULL,
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (customer_id) REFERENCES customers (id)
            );
        """)
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                sku TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                stock_quantity INTEGER DEFAULT 0
            );
        """)
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Insert seed data if customers table is empty
        cursor = await self._conn.execute("SELECT count(*) as count FROM customers")
        row = await cursor.fetchone()
        count = row["count"] if row else 0
        await cursor.close()

        if count == 0:
            await self._conn.execute(
                "INSERT INTO customers (id, name, email, company) VALUES (1, 'Alice Smith', 'alice@example.com', 'Acme Corp')"
            )
            await self._conn.execute(
                "INSERT INTO customers (id, name, email, company) VALUES (2, 'Bob Jones', 'bob@example.com', 'Stark Industries')"
            )
            await self._conn.execute(
                "INSERT INTO customers (id, name, email, company) VALUES (3, 'Bruce Wayne', 'bruce@wayne.com', 'Wayne Enterprises')"
            )
            await self._conn.execute(
                "INSERT INTO orders (id, customer_id, total_amount, status) VALUES (101, 1, 3498.00, 'completed')"
            )
            await self._conn.execute(
                "INSERT INTO orders (id, customer_id, total_amount, status) VALUES (102, 2, 999.00, 'processing')"
            )
            await self._conn.execute(
                "INSERT INTO orders (id, customer_id, total_amount, status) VALUES (103, 3, 450.00, 'completed')"
            )
            await self._conn.execute(
                "INSERT INTO products (id, sku, name, price, stock_quantity) VALUES (1, 'SRV-001', 'High-Performance Gateway Server', 2499.00, 15)"
            )
            await self._conn.execute(
                "INSERT INTO products (id, sku, name, price, stock_quantity) VALUES (2, 'SW-002', 'ToolBridge Enterprise License', 999.00, 100)"
            )
            await self._conn.execute(
                "INSERT INTO products (id, sku, name, price, stock_quantity) VALUES (3, 'ACC-003', 'Hardware Security Module (HSM)', 450.00, 30)"
            )
            await self._conn.execute(
                "INSERT INTO users (id, username, email, role) VALUES (1, 'admin_super', 'admin@toolbridge.io', 'admin')"
            )
            await self._conn.execute(
                "INSERT INTO users (id, username, email, role) VALUES (2, 'operator_dev', 'operator@toolbridge.io', 'operator')"
            )
            await self._conn.execute(
                "INSERT INTO users (id, username, email, role) VALUES (3, 'analyst_ro', 'analyst@toolbridge.io', 'readonly')"
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
        try:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            await cursor.close()

    async def describe_table(self, table_name: str, schema: str = "public") -> list[dict[str, Any]]:
        await self.connect()
        cursor = await self._conn.execute(f"PRAGMA table_info({table_name});")
        try:
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
        finally:
            await cursor.close()

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
        sqlite_query = re.sub(r"\$\d+", "?", query)

        cursor = await asyncio.wait_for(
            self._conn.execute(sqlite_query, params),
            timeout=timeout_seconds,
        )
        try:
            rows = await cursor.fetchmany(max_rows)
            return [dict(r) for r in rows]
        except asyncio.TimeoutError:
            raise DatabaseQueryTimeoutError(f"Query timed out after {timeout_seconds} seconds.")
        except Exception as e:
            raise RuntimeError(f"Database Execution Error: {e}") from e
        finally:
            await cursor.close()


class ResilientPostgresBackend(DatabaseBackend):
    """Dual-mode database backend that attempts PostgreSQL and transparently falls back to SQLite."""

    def __init__(
        self,
        postgres_backend: PostgresBackend | None = None,
        sqlite_backend: SQLiteTestBackend | None = None,
        fallback_db_path: str = "./data/sample_postgres.db",
    ) -> None:
        self.postgres_backend = postgres_backend or PostgresBackend()
        self.sqlite_backend = sqlite_backend or SQLiteTestBackend(db_path=fallback_db_path)
        self._active_backend: DatabaseBackend = self.postgres_backend
        self._is_fallback: bool = False

    @property
    def is_fallback(self) -> bool:
        """Whether the backend is currently operating in fallback SQLite mode."""
        return self._is_fallback

    async def connect(self) -> None:
        """Attempt PostgreSQL connection with graceful automatic fallback to SQLite."""
        force_sqlite = os.environ.get("POSTGRES_BACKEND", "").lower() == "sqlite"
        if force_sqlite:
            self._active_backend = self.sqlite_backend
            self._is_fallback = True
            await self.sqlite_backend.connect()
            return

        # Fast TCP pre-flight check to avoid long timeouts on closed ports
        port_open = False
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.postgres_backend.host, self.postgres_backend.port),
                timeout=0.25,
            )
            writer.close()
            await writer.wait_closed()
            port_open = True
        except Exception:
            port_open = False

        if port_open:
            try:
                await self.postgres_backend.connect()
                self._active_backend = self.postgres_backend
                self._is_fallback = False
                return
            except Exception as e:
                logger.warning(f"PostgreSQL connection failed despite open port: {e}")

        # Fallback to local SQLite backend
        sys.stderr.write(
            f"[ToolBridge Postgres] Host unreachable at {self.postgres_backend.host}:{self.postgres_backend.port}. "
            f"Operating on embedded SQLite database ({self.sqlite_backend.db_path}) with sample schema.\n"
        )
        self._active_backend = self.sqlite_backend
        self._is_fallback = True
        await self.sqlite_backend.connect()

    async def disconnect(self) -> None:
        await self._active_backend.disconnect()

    async def list_tables(self, schema: str = "public") -> list[dict[str, Any]]:
        return await self._active_backend.list_tables(schema=schema)

    async def describe_table(self, table_name: str, schema: str = "public") -> list[dict[str, Any]]:
        return await self._active_backend.describe_table(table_name=table_name, schema=schema)

    async def execute_query(
        self,
        query: str,
        parameters: Sequence[Any] | None = None,
        timeout_seconds: float = 10.0,
        max_rows: int = 500,
    ) -> list[dict[str, Any]]:
        return await self._active_backend.execute_query(
            query=query,
            parameters=parameters,
            timeout_seconds=timeout_seconds,
            max_rows=max_rows,
        )
