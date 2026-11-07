"""Controlled PostgreSQL MCP Server exposing read-only inspection and query tools."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Mapping

from mcp.server.lowlevel.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

from toolbridge.security.guards.sql import SQLSecurityGuard, SQLSecurityError
from toolbridge.upstreams.postgres.backend import (
    DatabaseBackend,
    DatabaseConnectionError,
    DatabaseQueryTimeoutError,
    PostgresBackend,
    SQLiteTestBackend,
)

TOOL_LIST_TABLES = Tool(
    name="list_tables",
    description="List all available database tables and views in the designated schema.",
    input_schema={
        "type": "object",
        "properties": {
            "schema": {
                "type": "string",
                "description": "Database schema name (default: 'public').",
                "default": "public",
            },
        },
    },
)

TOOL_DESCRIBE_TABLE = Tool(
    name="describe_table",
    description="Retrieve schema column definitions, data types, nullability, and keys for a table.",
    input_schema={
        "type": "object",
        "properties": {
            "table_name": {
                "type": "string",
                "description": "Name of the table to describe.",
            },
            "schema": {
                "type": "string",
                "description": "Database schema name (default: 'public').",
                "default": "public",
            },
        },
        "required": ["table_name"],
    },
)

TOOL_EXECUTE_QUERY = Tool(
    name="execute_query",
    description="Execute an approved read-only parameterized SQL query (SELECT, WITH, EXPLAIN only).",
    input_schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Parameterized SQL query using placeholders ($1, $2). Only read-only queries are permitted.",
            },
            "parameters": {
                "type": "array",
                "description": "Optional list of parameter values corresponding to query placeholders.",
                "items": {},
                "default": [],
            },
            "timeout_seconds": {
                "type": "number",
                "description": "Query execution timeout in seconds (default: 10.0, max: 30.0).",
                "default": 10.0,
            },
            "max_rows": {
                "type": "integer",
                "description": "Maximum number of rows to return (default: 100, max: 500).",
                "default": 100,
                "minimum": 1,
                "maximum": 500,
            },
        },
        "required": ["query"],
    },
)

ALL_POSTGRES_TOOLS: list[Tool] = [
    TOOL_LIST_TABLES,
    TOOL_DESCRIBE_TABLE,
    TOOL_EXECUTE_QUERY,
]


class PostgresMCPServer:
    """PostgreSQL MCP Server with read-only AST query guard and connection pooling."""

    def __init__(
        self,
        backend: DatabaseBackend | None = None,
        max_allowed_rows: int = 500,
    ) -> None:
        """Initialize the server with a database backend and SQL security guard."""
        self.backend = backend or self._create_default_backend()
        self.guard = SQLSecurityGuard(max_allowed_rows=max_allowed_rows)
        self.server = Server(
            name="toolbridge-postgres",
            version="0.1.0",
            on_list_tools=self._handle_list_tools,
            on_call_tool=self._handle_call_tool,
        )

    def _create_default_backend(self) -> DatabaseBackend:
        """Create a PostgresBackend configured from environment variables."""
        return PostgresBackend(
            host=os.environ.get("POSTGRES_READONLY_HOST", "localhost"),
            port=int(os.environ.get("POSTGRES_READONLY_PORT", 5432)),
            database=os.environ.get("POSTGRES_READONLY_DB", "toolbridge_demo"),
            user=os.environ.get("POSTGRES_READONLY_USER", "mcp_readonly"),
            password=os.environ.get("POSTGRES_READONLY_PASSWORD", ""),
            connect_timeout=float(os.environ.get("POSTGRES_CONNECT_TIMEOUT", 5.0)),
        )

    async def _handle_list_tools(
        self,
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        """Return available PostgreSQL tools."""
        return ListToolsResult(tools=ALL_POSTGRES_TOOLS)

    async def _handle_call_tool(
        self,
        ctx: ServerRequestContext,
        params: CallToolRequestParams,
    ) -> CallToolResult:
        """Intercept and route tool calls to secured database handlers."""
        tool_name = params.name
        args = params.arguments or {}

        try:
            if tool_name == "list_tables":
                return await self.tool_list_tables(args)
            elif tool_name == "describe_table":
                return await self.tool_describe_table(args)
            elif tool_name == "execute_query":
                return await self.tool_execute_query(args)
            else:
                return self._error_result(f"Unknown PostgreSQL tool: '{tool_name}'")
        except SQLSecurityError as e:
            return self._error_result(f"Security Violation: {e}")
        except DatabaseConnectionError as e:
            return self._error_result(f"Connection Error: {e}")
        except DatabaseQueryTimeoutError as e:
            return self._error_result(f"Timeout Error: {e}")
        except FileNotFoundError as e:
            return self._error_result(f"Not Found: {e}")
        except Exception as e:
            return self._error_result(f"Execution Error: {e}")

    # --- Tool Handlers ---

    async def tool_list_tables(self, args: Mapping[str, Any]) -> CallToolResult:
        """List tables and views in the schema."""
        schema = str(args.get("schema", "public"))
        tables = await self.backend.list_tables(schema=schema)
        payload = {
            "schema": schema,
            "total_tables": len(tables),
            "tables": tables,
        }
        return self._success_result(json.dumps(payload, indent=2))

    async def tool_describe_table(self, args: Mapping[str, Any]) -> CallToolResult:
        """Describe table columns and types."""
        table_name = args.get("table_name")
        if not table_name:
            return self._error_result("Missing required argument: 'table_name'")

        schema = str(args.get("schema", "public"))
        columns = await self.backend.describe_table(table_name=table_name, schema=schema)
        payload = {
            "table_name": table_name,
            "schema": schema,
            "columns": columns,
        }
        return self._success_result(json.dumps(payload, indent=2))

    async def tool_execute_query(self, args: Mapping[str, Any]) -> CallToolResult:
        """Validate query through AST guard and execute with parameters."""
        raw_query = args.get("query")
        if not raw_query:
            return self._error_result("Missing required argument: 'query'")

        parameters = args.get("parameters") or []
        timeout_seconds = min(float(args.get("timeout_seconds", 10.0)), 30.0)
        max_rows = min(max(int(args.get("max_rows", 100)), 1), self.guard.max_allowed_rows)

        # 1. AST Security Validation (Throws SQLSecurityError if mutating or multi-statement)
        validated_sql = self.guard.validate_read_only_query(raw_query)

        # 2. Database Execution
        rows = await self.backend.execute_query(
            query=validated_sql,
            parameters=parameters,
            timeout_seconds=timeout_seconds,
            max_rows=max_rows,
        )

        payload = {
            "query": validated_sql,
            "rows_returned": len(rows),
            "data": rows,
        }
        return self._success_result(json.dumps(payload, indent=2, default=str))

    # --- Helpers ---

    def _success_result(self, text: str) -> CallToolResult:
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            is_error=False,
        )

    def _error_result(self, message: str) -> CallToolResult:
        return CallToolResult(
            content=[TextContent(type="text", text=message)],
            is_error=True,
        )


def create_postgres_server(backend: DatabaseBackend | None = None) -> Server:
    """Factory creating an MCP low-level Server for PostgreSQL inspection and queries."""
    app = PostgresMCPServer(backend=backend)
    return app.server


async def main() -> None:
    """Run the PostgreSQL MCP server over stdio."""
    app = PostgresMCPServer()
    try:
        await app.backend.connect()
    except Exception as e:
        sys.stderr.write(f"Warning: Initial database connection failed: {e}\n")

    async with stdio_server() as (read_stream, write_stream):
        init_options = app.server.create_initialization_options()
        try:
            await app.server.run(read_stream, write_stream, init_options)
        finally:
            await app.backend.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
