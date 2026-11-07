"""Integration tests for PostgresMCPServer, covering discovery, queries, security, and failures."""
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any
import pytest

from mcp.types import CallToolRequestParams, PaginatedRequestParams
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

from toolbridge.upstreams.postgres.server import PostgresMCPServer, ALL_POSTGRES_TOOLS
from toolbridge.upstreams.postgres.backend import (
    DatabaseConnectionError,
    DatabaseQueryTimeoutError,
    PostgresBackend,
    SQLiteTestBackend,
)


@pytest.fixture
def test_server():
    """Create a PostgresMCPServer configured with the hermetic SQLite test backend."""
    backend = SQLiteTestBackend(db_path=":memory:")
    server_app = PostgresMCPServer(backend=backend, max_allowed_rows=100)
    return server_app, backend


@pytest.mark.integration
@pytest.mark.asyncio
async def test_postgres_tool_discovery(test_server):
    """Verify tool discovery exposes all three PostgreSQL inspection and query tools."""
    server_app, _ = test_server
    result = await server_app._handle_list_tools(None, PaginatedRequestParams())

    tool_names = [t.name for t in result.tools]
    assert "list_tables" in tool_names
    assert "describe_table" in tool_names
    assert "execute_query" in tool_names

    for t in result.tools:
        assert t.description
        assert t.input_schema["type"] == "object"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_tables_tool(test_server):
    """Verify listing tables returns available schema tables."""
    server_app, _ = test_server
    params = CallToolRequestParams(name="list_tables", arguments={"schema": "public"})
    res = await server_app._handle_call_tool(None, params)

    assert res.is_error is False
    payload = json.loads(res.content[0].text)
    assert payload["total_tables"] >= 2
    table_names = [t["table_name"] for t in payload["tables"]]
    assert "customers" in table_names
    assert "orders" in table_names


@pytest.mark.integration
@pytest.mark.asyncio
async def test_describe_table_tool(test_server):
    """Verify describing a table returns column definitions and data types."""
    server_app, _ = test_server
    params = CallToolRequestParams(name="describe_table", arguments={"table_name": "customers"})
    res = await server_app._handle_call_tool(None, params)

    assert res.is_error is False
    payload = json.loads(res.content[0].text)
    assert payload["table_name"] == "customers"
    col_names = [c["column_name"] for c in payload["columns"]]
    assert "id" in col_names
    assert "name" in col_names
    assert "email" in col_names


@pytest.mark.integration
@pytest.mark.asyncio
async def test_execute_query_parameterized(test_server):
    """Verify executing read-only query with parameters returns expected rows."""
    server_app, _ = test_server
    query = "SELECT id, name, email FROM customers WHERE id = $1"
    params = CallToolRequestParams(
        name="execute_query",
        arguments={"query": query, "parameters": [1]},
    )
    res = await server_app._handle_call_tool(None, params)

    assert res.is_error is False
    payload = json.loads(res.content[0].text)
    assert payload["rows_returned"] == 1
    assert payload["data"][0]["name"] == "Alice Smith"
    assert payload["data"][0]["email"] == "alice@example.com"


@pytest.mark.security
@pytest.mark.asyncio
@pytest.mark.parametrize("malicious_sql", [
    "INSERT INTO customers (id, name, email) VALUES (99, 'Evil', 'evil@hacker.com')",
    "UPDATE customers SET name = 'Hacked' WHERE id = 1",
    "DELETE FROM orders WHERE id = 101",
    "DROP TABLE orders",
    "ALTER TABLE customers ADD COLUMN secret text",
    "SELECT * FROM customers; DROP TABLE orders;",
    "SELECT * INTO new_customers FROM customers",
])
async def test_execute_query_blocks_mutations(test_server, malicious_sql: str):
    """Verify all mutating statements and multi-statements return security errors."""
    server_app, _ = test_server
    params = CallToolRequestParams(
        name="execute_query",
        arguments={"query": malicious_sql},
    )
    res = await server_app._handle_call_tool(None, params)

    assert res.is_error is True
    assert "Security Violation" in res.content[0].text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_postgres_connection_failure_handling():
    """Verify attempting to connect to an unreachable PostgreSQL host returns clean error."""
    # Configure backend pointing to non-existent port with small timeout
    unreachable_backend = PostgresBackend(
        host="127.0.0.1",
        port=59999,  # Closed port
        connect_timeout=0.5,
    )
    server_app = PostgresMCPServer(backend=unreachable_backend)

    params = CallToolRequestParams(name="list_tables", arguments={})
    res = await server_app._handle_call_tool(None, params)

    assert res.is_error is True
    assert "Connection Error" in res.content[0].text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_query_timeout_handling(test_server, monkeypatch):
    """Verify slow queries exceeding timeout raise DatabaseQueryTimeoutError."""
    server_app, backend = test_server

    # Simulate query timeout in backend
    async def mock_execute_query(*args, **kwargs):
        raise DatabaseQueryTimeoutError("Query execution timed out after 0.1 seconds.")

    monkeypatch.setattr(backend, "execute_query", mock_execute_query)

    params = CallToolRequestParams(
        name="execute_query",
        arguments={"query": "SELECT * FROM customers", "timeout_seconds": 0.1},
    )
    res = await server_app._handle_call_tool(None, params)

    assert res.is_error is True
    assert "Timeout Error" in res.content[0].text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_stdio_postgres_server_e2e():
    """End-to-End test running PostgresMCPServer in a subprocess over stdio using MCP SDK v2."""
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-c", """
import asyncio
from toolbridge.upstreams.postgres.server import PostgresMCPServer
from toolbridge.upstreams.postgres.backend import SQLiteTestBackend
from mcp.server.stdio import stdio_server

async def run():
    backend = SQLiteTestBackend(':memory:')
    await backend.connect()
    app = PostgresMCPServer(backend=backend)
    async with stdio_server() as (read, write):
        await app.server.run(read, write, app.server.create_initialization_options())

asyncio.run(run())
"""],
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # 1. Handshake
            await session.initialize()

            # 2. Discover Tools
            tools = await session.list_tools()
            assert any(t.name == "list_tables" for t in tools.tools)
            assert any(t.name == "execute_query" for t in tools.tools)

            # 3. Call list_tables
            tables_res = await session.call_tool("list_tables", {"schema": "public"})
            assert tables_res.is_error is False
            assert "customers" in tables_res.content[0].text

            # 4. Call execute_query
            query_res = await session.call_tool(
                "execute_query",
                {"query": "SELECT name FROM customers WHERE id = $1", "parameters": [1]},
            )
            assert query_res.is_error is False
            assert "Alice Smith" in query_res.content[0].text

            # 5. Verify Mutation Blocked Over stdio
            blocked_res = await session.call_tool(
                "execute_query",
                {"query": "DROP TABLE customers"},
            )
            assert blocked_res.is_error is True
            assert "Security Violation" in blocked_res.content[0].text
