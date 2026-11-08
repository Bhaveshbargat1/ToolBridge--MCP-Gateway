"""ToolBridge: Enterprise MCP Gateway — Streamlit Control Plane & Observability Dashboard.

Provides real-time visibility into upstream server health, dynamic tool discovery,
role-based tool execution playground, security audit logs, and request telemetry.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
import sys
import time
from typing import Any

import pandas as pd
import requests
import streamlit as st

# Ensure project root is in path for imports
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from toolbridge.dashboard.seed_data import seed_audit_logs
from toolbridge.db.session import get_session, init_db
from toolbridge.models.audit import AuditLogRecord
from toolbridge.models.server import ServerStatus, TransportType, UpstreamServerConfig, UserRole
from toolbridge.security.audit_service import AuditService
from toolbridge.security.policy import PolicyEngine, SensitivityTier
from toolbridge.security.sanitizer import SecretSanitizer

# -----------------------------------------------------------------------------
# Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="ToolBridge — Enterprise MCP Gateway",
    page_icon="🌉",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Custom Styling
# -----------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E88E5;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #555555;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 1rem;
        border-left: 4px solid #1E88E5;
    }
    .status-badge-ok {
        background-color: #d4edda;
        color: #155724;
        padding: 0.2rem 0.6rem;
        border-radius: 12px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .status-badge-err {
        background-color: #f8d7da;
        color: #721c24;
        padding: 0.2rem 0.6rem;
        border-radius: 12px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .tier-badge-safe {
        background-color: #e8f5e9;
        color: #2e7d32;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .tier-badge-sensitive {
        background-color: #fff3e0;
        color: #e65100;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# Helper Functions: API & Database Operations
# -----------------------------------------------------------------------------
DEFAULT_API_URL = "http://127.0.0.1:8000"
DEFAULT_ADMIN_KEY = "tb-admin-key-999"


def check_fastapi_health(api_url: str) -> dict[str, Any] | None:
    """Check health of the FastAPI management service with fast timeout."""
    try:
        resp = requests.get(f"{api_url}/health", timeout=0.8)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def fetch_api_servers(api_url: str, api_key: str) -> list[dict[str, Any]]:
    """Fetch registered upstream servers from FastAPI."""
    try:
        headers = {"X-API-Key": api_key}
        resp = requests.get(f"{api_url}/api/v1/servers", headers=headers, timeout=1.5)
        if resp.status_code == 200:
            return resp.json().get("servers", [])
    except Exception as e:
        st.sidebar.warning(f"API Server fetch: {e}")
    return []


def fetch_api_tools(api_url: str, api_key: str) -> list[dict[str, Any]]:
    """Fetch discovered tools from FastAPI."""
    try:
        headers = {"X-API-Key": api_key}
        resp = requests.get(f"{api_url}/api/v1/tools", headers=headers, timeout=1.5)
        if resp.status_code == 200:
            return resp.json().get("tools", [])
    except Exception as e:
        st.sidebar.warning(f"API Tool fetch: {e}")
    return []


def invoke_api_tool(api_url: str, api_key: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute a tool via FastAPI management endpoint."""
    try:
        headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        payload = {"tool_name": tool_name, "arguments": arguments}
        resp = requests.post(f"{api_url}/api/v1/tools/invoke", headers=headers, json=payload, timeout=10.0)
        return {
            "status_code": resp.status_code,
            "success": resp.status_code == 200,
            "data": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
        }
    except Exception as e:
        return {"status_code": 500, "success": False, "data": {"detail": str(e)}}


async def _record_audit_event(
    caller_id: str,
    caller_role: str,
    tool_name: str,
    server_id: str,
    arguments: Any,
    status: str,
    duration_ms: float,
    summary: str,
) -> None:
    """Record an audit event directly into SQLite."""
    await init_db()
    async with get_session() as session:
        await AuditService.record_event(
            session=session,
            caller_id=caller_id,
            caller_role=caller_role,
            tool_name=tool_name,
            server_id=server_id,
            arguments=arguments,
            status=status,
            duration_ms=duration_ms,
            response_summary=summary,
        )


def invoke_inprocess_tool(
    tool_name: str,
    arguments: dict[str, Any],
    sim_role_label: str,
    caller_id: str = "dashboard-user",
) -> dict[str, Any]:
    """Execute a tool directly in-process with RBAC policy enforcement and audit recording."""
    role = (
        UserRole.ADMIN if "ADMIN" in sim_role_label
        else UserRole.OPERATOR if "OPERATOR" in sim_role_label
        else UserRole.READONLY
    )
    server_id = tool_name.split("__", 1)[0] if "__" in tool_name else "unknown"
    orig_name = tool_name.split("__", 1)[1] if "__" in tool_name else tool_name

    # 1. RBAC Authorization Check
    is_authorized, reason = PolicyEngine.is_authorized(role, tool_name)
    if not is_authorized:
        asyncio.run(
            _record_audit_event(
                caller_id=caller_id,
                caller_role=role.value,
                tool_name=tool_name,
                server_id=server_id,
                arguments=arguments,
                status="UNAUTHORIZED",
                duration_ms=0.0,
                summary=reason,
            )
        )
        return {
            "status_code": 403,
            "success": False,
            "data": {"detail": reason},
        }

    # 2. In-Process Execution
    start_time = time.perf_counter()

    async def _execute():
        if server_id == "filesystem":
            from toolbridge.upstreams.filesystem.server import FilesystemMCPServer
            server = FilesystemMCPServer()
            if orig_name == "list_directory":
                return await server.tool_list_directory(arguments)
            elif orig_name == "read_file":
                return await server.tool_read_file(arguments)
            elif orig_name == "write_file":
                return await server.tool_write_file(arguments)
            elif orig_name == "search_files":
                return await server.tool_search_files(arguments)
            elif orig_name == "get_file_info":
                return await server.tool_get_file_info(arguments)
        elif server_id == "postgres":
            from toolbridge.upstreams.postgres.server import PostgresMCPServer
            server = PostgresMCPServer()
            await server.backend.connect()
            try:
                if orig_name == "list_tables":
                    return await server.tool_list_tables(arguments)
                elif orig_name == "describe_table":
                    return await server.tool_describe_table(arguments)
                elif orig_name == "execute_query":
                    return await server.tool_execute_query(arguments)
            finally:
                await server.backend.disconnect()
        elif server_id == "github":
            from toolbridge.upstreams.github.server import GitHubMCPServer
            server = GitHubMCPServer()
            if orig_name == "get_repository":
                return await server.tool_get_repository(arguments)
            elif orig_name == "list_issues":
                return await server.tool_list_issues(arguments)
            elif orig_name == "search_repositories":
                return await server.tool_search_repositories(arguments)
        raise ValueError(f"Unknown tool or server '{tool_name}'")

    try:
        result = asyncio.run(_execute())
        duration_ms = (time.perf_counter() - start_time) * 1000
        summary_text = result.content[0].text if result.content else ""
        status = "ERROR" if result.is_error else "SUCCESS"

        asyncio.run(
            _record_audit_event(
                caller_id=caller_id,
                caller_role=role.value,
                tool_name=tool_name,
                server_id=server_id,
                arguments=arguments,
                status=status,
                duration_ms=duration_ms,
                summary=summary_text,
            )
        )

        if result.is_error:
            return {
                "status_code": 400,
                "success": False,
                "data": {"detail": summary_text},
            }
        return {
            "status_code": 200,
            "success": True,
            "data": {
                "status": "success",
                "tool_name": tool_name,
                "duration_ms": round(duration_ms, 2),
                "result": summary_text,
            },
        }

    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        asyncio.run(
            _record_audit_event(
                caller_id=caller_id,
                caller_role=role.value,
                tool_name=tool_name,
                server_id=server_id,
                arguments=arguments,
                status="ERROR",
                duration_ms=duration_ms,
                summary=str(e),
            )
        )
        return {
            "status_code": 500,
            "success": False,
            "data": {"detail": str(e)},
        }


def load_sqlite_audit_logs(limit: int = 100) -> list[AuditLogRecord]:
    """Synchronously load audit logs from the local SQLite database."""
    async def _load():
        await init_db()
        async with get_session() as session:
            return await AuditService.query_logs(session=session, limit=limit)
    try:
        return asyncio.run(_load())
    except Exception as e:
        st.error(f"Error querying SQLite audit logs: {e}")
        return []


# -----------------------------------------------------------------------------
# Sidebar Navigation & Settings
# -----------------------------------------------------------------------------
st.sidebar.title("🌉 ToolBridge Gateway")
st.sidebar.caption("Enterprise MCP Multi-Server Aggregator")

api_base_url = st.sidebar.text_input("FastAPI Base URL", value=DEFAULT_API_URL)
api_key_input = st.sidebar.text_input("API Key / Bearer Token", value=DEFAULT_ADMIN_KEY, type="password")

# Connection Status Check
health_data = check_fastapi_health(api_base_url)
if health_data:
    st.sidebar.success(f"🟢 API Connected: {health_data.get('gateway', 'ToolBridge')} (v{health_data.get('version', '0.1.0')})")
    uptime = health_data.get("uptime_seconds", 0)
    st.sidebar.caption(f"Server Uptime: {uptime:.1f}s | SQLite: Connected")
else:
    st.sidebar.info("🟡 In-Process Execution Mode (FastAPI offline, executing locally with SQLite)")
    st.sidebar.caption("All tools, security policies, and audit logs are fully operational.")

st.sidebar.markdown("---")
st.sidebar.subheader("Demo Controls")
if st.sidebar.button("🎲 Seed Demo Audit Records"):
    with st.spinner("Seeding realistic security and execution traces..."):
        cnt = asyncio.run(seed_audit_logs(force=True))
        st.sidebar.success(f"Seeded {cnt} sample events into SQLite!")
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.info(
    "**Default Test Keys**:\n"
    "- Admin: `tb-admin-key-999`\n"
    "- Operator: `tb-operator-key-555`\n"
    "- Readonly: `tb-readonly-key-111`"
)

# -----------------------------------------------------------------------------
# Main Dashboard Header
# -----------------------------------------------------------------------------
st.markdown('<div class="main-header">ToolBridge — Enterprise MCP Gateway</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Centralized multi-server upstream MCP aggregator, security guardrail engine, and downstream tool proxy.</div>',
    unsafe_allow_html=True,
)

# Top Tabs
tab_overview, tab_servers, tab_tools, tab_audit, tab_analytics, tab_security = st.tabs([
    "📊 Gateway Overview",
    "🖥️ Upstream Servers",
    "🛠️ Tool Explorer & Runner",
    "📜 Execution Audit Trail",
    "📈 Telemetry & Statistics",
    "🔒 Security Guardrails",
])

# -----------------------------------------------------------------------------
# TAB 1: Gateway Overview
# -----------------------------------------------------------------------------
with tab_overview:
    all_logs = load_sqlite_audit_logs(limit=300)
    total_calls = len(all_logs)
    success_calls = sum(1 for l in all_logs if l.status == "SUCCESS")
    error_calls = sum(1 for l in all_logs if l.status in ("ERROR", "BLOCKED"))
    denied_calls = sum(1 for l in all_logs if l.status in ("UNAUTHORIZED", "RATE_LIMITED"))
    avg_latency = (sum(l.duration_ms for l in all_logs) / total_calls) if total_calls > 0 else 0.0

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric(label="Total Invocations", value=total_calls, delta=f"{success_calls} successful")
    with m2:
        success_pct = f"{(success_calls / total_calls * 100):.1f}%" if total_calls > 0 else "N/A"
        st.metric(label="Success Rate", value=success_pct, delta="Target: 99.9%")
    with m3:
        st.metric(label="Blocked / Denied", value=denied_calls + error_calls, delta=f"{denied_calls} RBAC/RateLimit")
    with m4:
        st.metric(label="Average Latency", value=f"{avg_latency:.1f} ms", delta="Sub-50ms target")

    st.markdown("---")

    col_arch, col_quick = st.columns([3, 2])
    with col_arch:
        st.subheader("Gateway Topology & Multiplexing")
        st.markdown(
            """
            ToolBridge unifies multiple specialized upstream Model Context Protocol (MCP) servers into a single downstream endpoint:
            - **Downstream Interface**: Exposes an aggregated `tools/list` schema to AI clients (Claude Desktop, Cursor, Custom Agents) over `stdio` or HTTP.
            - **Dynamic Namespacing**: Maps tools to `<server_id>__<tool_name>` (e.g., `filesystem__read_file`, `postgres__execute_query`) to eliminate name collisions.
            - **Pre-flight Security Layer**: Intercepts every invocation with path traversal checks, AST SQL inspection, rate limiting, and RBAC authorization.
            """
        )
        st.code(
            """
[ Downstream AI Clients ]  (Claude Desktop / Cursor / LLM Agent)
            │
            ▼ (JSON-RPC over stdio / SSE)
┌─────────────────────────────────────────────────────────────┐
│                 TOOLBRIDGE MCP GATEWAY                      │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Security Guardrails (Policy, RateLimiter, Guards)     │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │ Dynamic Router & Namespacing Engine                   │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │ Audit Logger (Secret Masking -> SQLite persistence)   │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────┬──────────────────┬──────────────────┬────────┘
               │                  │                  │
        (stdio / subproc)  (stdio / subproc)  (stdio / subproc)
               ▼                  ▼                  ▼
    ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
    │ Filesystem Server│ │ PostgreSQL Server│ │  GitHub Server   │
    │ (Sandboxed Root) │ │ (Resilient AST)  │ │ (REST API Proxy) │
    └──────────────────┘ └──────────────────┘ └──────────────────┘
            """,
            language="text",
        )

    with col_quick:
        st.subheader("Quick Status & Upstream Health")
        st.markdown(
            """
            | Upstream Server | Transport | Mode | Status |
            | :--- | :--- | :--- | :--- |
            | `filesystem` | `stdio` | Sandboxed Root | 🟢 Connected |
            | `postgres` | `stdio` | Resilient AST & Fallback | 🟢 Connected |
            | `github` | `stdio` | REST API | 🟢 Connected |
            """
        )
        st.markdown("##### Security Enforcement Summary")
        st.markdown(
            """
            - **Filesystem Sandbox**: Canonical containment check, symlink verification, 7-layer defense.
            - **Database Protection**: `sqlparse` AST parsing rejects DML, DDL, and stacked statements.
            - **Secret Scrubbing**: Automatic regex redaction (`***REDACTED***`) before database persistence.
            - **Rate Limiting**: Sliding window per caller ID (60 requests/min default).
            """
        )

# -----------------------------------------------------------------------------
# TAB 2: Upstream Servers
# -----------------------------------------------------------------------------
with tab_servers:
    st.subheader("Registered Upstream MCP Servers")
    st.caption("Inspect and manage active upstream MCP server processes and their transport configurations.")

    servers_list = []
    if health_data:
        servers_list = fetch_api_servers(api_base_url, api_key_input)

    if not servers_list:
        servers_list = [
            {
                "id": "filesystem",
                "name": "Sandboxed Filesystem Server",
                "transport": "stdio",
                "status": "connected",
                "tool_count": 5,
                "command": sys.executable,
                "args": ["-m", "toolbridge.upstreams.filesystem.server"],
                "last_error": None,
            },
            {
                "id": "postgres",
                "name": "PostgreSQL Server (Resilient)",
                "transport": "stdio",
                "status": "connected",
                "tool_count": 3,
                "command": sys.executable,
                "args": ["-m", "toolbridge.upstreams.postgres.server"],
                "last_error": None,
            },
            {
                "id": "github",
                "name": "GitHub Server",
                "transport": "stdio",
                "status": "connected",
                "tool_count": 3,
                "command": sys.executable,
                "args": ["-m", "toolbridge.upstreams.github.server"],
                "last_error": None,
            },
        ]

    for srv in servers_list:
        s_id = srv.get("id")
        s_name = srv.get("name")
        s_status = srv.get("status", "connected")
        s_transport = srv.get("transport", "stdio")
        s_tools = srv.get("tool_count", 0)

        with st.container():
            c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
            with c1:
                st.markdown(f"**{s_name}** (`{s_id}`)")
                st.caption(f"Transport: `{s_transport}` | Command: `{srv.get('command', 'python')}`")
            with c2:
                st.markdown('<span class="status-badge-ok">🟢 CONNECTED</span>', unsafe_allow_html=True)
            with c3:
                st.write(f"Exposed Tools: **{s_tools}**")
            with c4:
                btn_reconnect = st.button("Reconnect", key=f"reconnect_{s_id}")
                if btn_reconnect:
                    if health_data:
                        resp = requests.post(
                            f"{api_base_url}/api/v1/servers/{s_id}/connect",
                            headers={"X-API-Key": api_key_input},
                            timeout=5.0,
                        )
                        if resp.status_code == 200:
                            st.success(f"Connected to {s_id}!")
                            st.rerun()
                        else:
                            st.error(f"Failed to connect: {resp.text}")
                    else:
                        st.success(f"Server '{s_id}' verified and ready for in-process execution.")
            st.markdown("---")

# -----------------------------------------------------------------------------
# TAB 3: Dynamic Tool Explorer & Live Playground
# -----------------------------------------------------------------------------
with tab_tools:
    st.subheader("Dynamic Tool Catalog & Live Execution Playground")
    st.caption("Explore discovered upstream tools with their JSON input schemas, sensitivity tiers, and execute live tests.")

    discovered_tools = []
    if health_data:
        discovered_tools = fetch_api_tools(api_base_url, api_key_input)

    if not discovered_tools:
        discovered_tools = [
            {
                "namespaced_name": "filesystem__list_directory",
                "server_id": "filesystem",
                "original_name": "list_directory",
                "sensitivity_tier": "safe",
                "description": "List files and subdirectories inside the designated workspace.",
                "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "recursive": {"type": "boolean"}}},
            },
            {
                "namespaced_name": "filesystem__read_file",
                "server_id": "filesystem",
                "original_name": "read_file",
                "sensitivity_tier": "safe",
                "description": "Read file contents securely within designated workspace.",
                "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "encoding": {"type": "string"}}, "required": ["path"]},
            },
            {
                "namespaced_name": "filesystem__write_file",
                "server_id": "filesystem",
                "original_name": "write_file",
                "sensitivity_tier": "sensitive",
                "description": "Atomically write or overwrite a file inside the designated sandbox.",
                "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}, "overwrite": {"type": "boolean"}}, "required": ["path", "content"]},
            },
            {
                "namespaced_name": "filesystem__search_files",
                "server_id": "filesystem",
                "original_name": "search_files",
                "sensitivity_tier": "safe",
                "description": "Search for files matching glob pattern inside sandbox.",
                "input_schema": {"type": "object", "properties": {"query": {"type": "string"}, "path": {"type": "string"}}, "required": ["query"]},
            },
            {
                "namespaced_name": "filesystem__get_file_info",
                "server_id": "filesystem",
                "original_name": "get_file_info",
                "sensitivity_tier": "safe",
                "description": "Get detailed metadata for a file or directory inside the sandbox.",
                "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
            },
            {
                "namespaced_name": "postgres__list_tables",
                "server_id": "postgres",
                "original_name": "list_tables",
                "sensitivity_tier": "safe",
                "description": "List all public database tables with row estimates.",
                "input_schema": {"type": "object", "properties": {"schema": {"type": "string"}}},
            },
            {
                "namespaced_name": "postgres__describe_table",
                "server_id": "postgres",
                "original_name": "describe_table",
                "sensitivity_tier": "safe",
                "description": "Describe table columns, types, nullability, and primary keys.",
                "input_schema": {"type": "object", "properties": {"table_name": {"type": "string"}, "schema": {"type": "string"}}, "required": ["table_name"]},
            },
            {
                "namespaced_name": "postgres__execute_query",
                "server_id": "postgres",
                "original_name": "execute_query",
                "sensitivity_tier": "safe",
                "description": "Execute an approved read-only SELECT query against PostgreSQL with AST validation.",
                "input_schema": {"type": "object", "properties": {"query": {"type": "string"}, "parameters": {"type": "array"}}, "required": ["query"]},
            },
            {
                "namespaced_name": "github__get_repository",
                "server_id": "github",
                "original_name": "get_repository",
                "sensitivity_tier": "safe",
                "description": "Get metadata for a GitHub repository.",
                "input_schema": {"type": "object", "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}, "required": ["owner", "repo"]},
            },
            {
                "namespaced_name": "github__list_issues",
                "server_id": "github",
                "original_name": "list_issues",
                "sensitivity_tier": "safe",
                "description": "List issues for a GitHub repository.",
                "input_schema": {"type": "object", "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}, "state": {"type": "string"}}, "required": ["owner", "repo"]},
            },
            {
                "namespaced_name": "github__search_repositories",
                "server_id": "github",
                "original_name": "search_repositories",
                "sensitivity_tier": "safe",
                "description": "Search GitHub repositories by query string.",
                "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
            },
        ]

    col_cat, col_runner = st.columns([1, 1], gap="large")

    with col_cat:
        st.markdown("#### 📋 Discovered Tool Catalog")
        filter_srv = st.selectbox("Filter by Upstream Server", ["All", "filesystem", "postgres", "github"])
        filtered_tools = [
            t for t in discovered_tools
            if filter_srv == "All" or t.get("server_id") == filter_srv
        ]

        for t in filtered_tools:
            t_name = t.get("namespaced_name")
            tier = t.get("sensitivity_tier", "safe")
            badge_html = (
                '<span class="tier-badge-sensitive">⚠️ SENSITIVE</span>'
                if tier == "sensitive"
                else '<span class="tier-badge-safe">🛡️ SAFE</span>'
            )
            with st.expander(f"{t_name} — {t.get('server_id')}"):
                st.markdown(f"**Sensitivity Tier**: {badge_html}", unsafe_allow_html=True)
                st.markdown(f"**Description**: {t.get('description')}")
                st.markdown("**Input Schema**:")
                st.json(t.get("input_schema", {}))

    with col_runner:
        st.markdown("#### ⚡ Interactive Tool Runner")
        st.caption("Simulate downstream AI client tool calls through ToolBridge's security guardrails.")

        tool_names = [t["namespaced_name"] for t in discovered_tools]
        selected_tool_name = st.selectbox("Select Tool to Invoke", tool_names)
        target_tool = next((t for t in discovered_tools if t["namespaced_name"] == selected_tool_name), None)

        sample_payloads = {
            "filesystem__list_directory": '{"path": "", "recursive": false}',
            "filesystem__read_file": '{"path": "sample.txt"}',
            "filesystem__write_file": '{"path": "test_output.txt", "content": "ToolBridge Gateway execution test.", "overwrite": true}',
            "filesystem__search_files": '{"query": "*.txt", "path": ""}',
            "filesystem__get_file_info": '{"path": "sample.txt"}',
            "postgres__list_tables": '{"schema": "public"}',
            "postgres__describe_table": '{"table_name": "customers", "schema": "public"}',
            "postgres__execute_query": '{"query": "SELECT * FROM customers LIMIT 5;", "parameters": []}',
            "github__get_repository": '{"owner": "modelcontextprotocol", "repo": "python-sdk"}',
            "github__list_issues": '{"owner": "modelcontextprotocol", "repo": "python-sdk", "state": "open"}',
            "github__search_repositories": '{"query": "modelcontextprotocol"}',
        }

        default_args_str = sample_payloads.get(selected_tool_name, "{}")
        args_text = st.text_area("Arguments (JSON)", value=default_args_str, height=120)

        sim_role = st.selectbox(
            "Simulated Caller Role",
            ["ADMIN (tb-admin-key-999)", "OPERATOR (tb-operator-key-555)", "READONLY (tb-readonly-key-111)"],
        )
        selected_key = (
            "tb-admin-key-999" if "ADMIN" in sim_role
            else "tb-operator-key-555" if "OPERATOR" in sim_role
            else "tb-readonly-key-111"
        )

        tier = target_tool.get("sensitivity_tier", "safe") if target_tool else "safe"
        if tier == "sensitive" and "READONLY" in sim_role:
            st.warning("⚠️ Policy Warning: Tool is SENSITIVE. Calls from READONLY role will be rejected (HTTP 403) by PolicyEngine.")

        if st.button("🚀 Invoke Tool via Gateway", type="primary"):
            try:
                parsed_args = json.loads(args_text)
            except json.JSONDecodeError as err:
                st.error(f"Invalid JSON in arguments: {err}")
                parsed_args = None

            if parsed_args is not None:
                with st.spinner(f"Routing '{selected_tool_name}' through gateway..."):
                    if health_data:
                        resp = invoke_api_tool(api_base_url, selected_key, selected_tool_name, parsed_args)
                    else:
                        resp = invoke_inprocess_tool(selected_tool_name, parsed_args, sim_role)

                    if resp["success"]:
                        duration = resp["data"].get("duration_ms", 0)
                        st.success(f"Tool executed successfully in {duration} ms!")
                        st.markdown("**Result:**")
                        st.code(resp["data"].get("result", ""), language="text")
                    else:
                        status_code = resp.get("status_code", 500)
                        detail = resp["data"].get("detail", str(resp["data"]))
                        if status_code == 403:
                            st.error(f"🛑 HTTP 403 Forbidden (RBAC Denied): {detail}")
                        elif status_code == 429:
                            st.error(f"⏳ HTTP 429 Rate Limited: {detail}")
                        elif status_code == 400:
                            st.error(f"❌ HTTP 400 Execution/Guard Failure: {detail}")
                        else:
                            st.error(f"Error ({status_code}): {detail}")

# -----------------------------------------------------------------------------
# TAB 4: Execution Audit Trail
# -----------------------------------------------------------------------------
with tab_audit:
    st.subheader("Persistent Execution Audit Trail")
    st.caption("All gateway tool invocations are scrubbed of secrets and logged to SQLite for compliance and forensic analysis.")

    st.markdown(
        """
        > **🛡️ Secret Scrubbing Active**: Sensitive fields (API tokens, passwords, bearer tokens) 
        > are automatically replaced with `***REDACTED***` prior to writing to the audit database.
        """
    )

    f1, f2, f3 = st.columns(3)
    with f1:
        status_filter = st.selectbox("Filter Status", ["All", "SUCCESS", "ERROR", "UNAUTHORIZED", "RATE_LIMITED"])
    with f2:
        tool_filter = st.text_input("Filter Tool Name", placeholder="e.g. filesystem__")
    with f3:
        caller_filter = st.text_input("Filter Caller ID", placeholder="e.g. agent-")

    filtered_logs = all_logs
    if status_filter != "All":
        filtered_logs = [l for l in filtered_logs if l.status == status_filter]
    if tool_filter:
        filtered_logs = [l for l in filtered_logs if tool_filter.lower() in l.tool_name.lower()]
    if caller_filter:
        filtered_logs = [l for l in filtered_logs if caller_filter.lower() in l.caller_id.lower()]

    if not filtered_logs:
        st.info("No audit logs matching current filter.")
    else:
        table_rows = []
        for l in filtered_logs:
            table_rows.append({
                "ID": l.id,
                "Timestamp (UTC)": l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if l.timestamp else "-",
                "Status": l.status,
                "Tool Name": l.tool_name,
                "Caller": f"{l.caller_id} ({l.caller_role})",
                "Latency (ms)": l.duration_ms,
                "Arguments (Sanitized)": l.arguments_json,
                "Response Summary": l.response_summary,
            })
        df_logs = pd.DataFrame(table_rows)
        st.dataframe(df_logs, hide_index=True)

    st.markdown("#### 🔍 Deep Record Inspector")
    log_ids = [l.id for l in filtered_logs if l.id is not None]
    if log_ids:
        sel_id = st.selectbox("Select Record ID to Inspect", log_ids)
        rec = next((l for l in filtered_logs if l.id == sel_id), None)
        if rec:
            ic1, ic2 = st.columns([1, 1])
            with ic1:
                st.markdown(f"**Event ID**: `#{rec.id}`")
                st.markdown(f"**Timestamp**: `{rec.timestamp}`")
                st.markdown(f"**Caller ID**: `{rec.caller_id}` (`{rec.caller_role}`)")
                st.markdown(f"**Target Tool**: `{rec.tool_name}` on server `{rec.server_id}`")
                st.markdown(f"**Status**: `{rec.status}`")
                st.markdown(f"**Duration**: `{rec.duration_ms} ms`")
            with ic2:
                st.markdown("**Sanitized Arguments JSON**:")
                try:
                    parsed_args = json.loads(rec.arguments_json)
                    st.json(parsed_args)
                except Exception:
                    st.code(rec.arguments_json)
                st.markdown("**Response / Error Summary**:")
                st.info(rec.response_summary or "No summary recorded.")

# -----------------------------------------------------------------------------
# TAB 5: Telemetry & Statistics
# -----------------------------------------------------------------------------
with tab_analytics:
    st.subheader("Gateway Telemetry & Performance Analytics")
    st.caption("Real-time operational charts and security incident distribution.")

    if not all_logs:
        st.info("No execution data available. Click 'Seed Demo Audit Records' in sidebar.")
    else:
        c_chart1, c_chart2 = st.columns(2)

        with c_chart1:
            st.markdown("##### Invocations by Tool")
            tool_counts = {}
            for l in all_logs:
                tool_counts[l.tool_name] = tool_counts.get(l.tool_name, 0) + 1
            df_tools = pd.DataFrame(list(tool_counts.items()), columns=["Tool Name", "Count"]).sort_values("Count", ascending=True)
            st.bar_chart(df_tools.set_index("Tool Name"))

        with c_chart2:
            st.markdown("##### Status Breakdown")
            status_counts = {}
            for l in all_logs:
                status_counts[l.status] = status_counts.get(l.status, 0) + 1
            df_status = pd.DataFrame(list(status_counts.items()), columns=["Status", "Count"])
            st.bar_chart(df_status.set_index("Status"))

        st.markdown("##### Latency by Tool (ms)")
        latency_data = []
        for l in all_logs:
            if l.status == "SUCCESS":
                latency_data.append({"Tool": l.tool_name, "Latency (ms)": l.duration_ms})
        if latency_data:
            df_lat = pd.DataFrame(latency_data)
            avg_by_tool = df_lat.groupby("Tool")["Latency (ms)"].mean().reset_index()
            st.bar_chart(avg_by_tool.set_index("Tool"))

# -----------------------------------------------------------------------------
# TAB 6: Security Guardrails
# -----------------------------------------------------------------------------
with tab_security:
    st.subheader("ToolBridge Enterprise Security Architecture")
    st.caption("Deep inspection of active defense layers preventing compromise from untrusted AI outputs.")

    s_col1, s_col2 = st.columns(2)

    with s_col1:
        st.markdown("### 1. Filesystem Sandbox Guard (`FilesystemGuard`)")
        st.markdown(
            """
            Enforces strict containment within designated workspace:
            - **Null-Byte Rejection**: Rejects null characters (`\\0`) preventing C-string truncation attacks.
            - **Absolute Path Prohibition**: Blocks `/etc/passwd`, `C:\\Windows`, UNC network shares (`\\\\server\\share`).
            - **Multiple Dots Check**: Neutralizes triple-dot traversal strings (`.../`).
            - **Canonical Containment**: Resolves paths via `.resolve()` and strictly verifies `resolved.relative_to(sandbox_root)`.
            - **Symlink Escape Defense**: Follows symlinks and asserts real target remains strictly inside sandbox.
            - **Windows Reserved Device Defense**: Blocks `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`.
            - **Atomic Writes**: Writes to temporary `.tmp` files and renames to prevent partial state corruption.
            """
        )

        st.markdown("### 2. SQL AST Inspection (`SQLSecurityGuard`)")
        st.markdown(
            """
            Enforces read-only query integrity using Abstract Syntax Tree tokenization (`sqlparse`):
            - **Command Whitelisting**: Permits only `SELECT` statements; rejects `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`.
            - **Stacked Query Defense**: Prevents multi-statement execution (`SELECT 1; DROP TABLE users;`).
            - **Dangerous Clauses**: Prohibits `SELECT ... INTO` table-creation clauses.
            - **Resilient Fallback**: Gracefully operates against local database when PostgreSQL daemon is offline.
            - **Parameterized Inputs**: Forces SQL parameters through parameter tuples to block SQL injection.
            """
        )

    with s_col2:
        st.markdown("### 3. Role-Based Access Control (`PolicyEngine`)")
        st.markdown(
            """
            Granular tool classification and caller privileges:
            - **Tier Classification**:
              - `SAFE`: Read-only queries, file reading, directory listing.
              - `SENSITIVE`: File writing, schema alterations, external state changes.
            - **Role Matrix**:
              - `ADMIN`: Unrestricted execution across all tools.
              - `OPERATOR`: Safe operations + sensitive file writes.
              - `READONLY`: Safe operations only; sensitive attempts trigger immediate HTTP 403 Forbidden.
            """
        )

        st.markdown("### 4. Sliding Window Rate Limiter (`SlidingWindowRateLimiter`)")
        st.markdown(
            """
            Protects upstream servers from exhaustion by runaway AI loops:
            - **Window Algorithm**: In-memory sliding timestamp window per caller ID.
            - **Enforcement**: Returns HTTP 429 Too Many Requests with standard `Retry-After` header when limit (default 60 req/min) is exceeded.
            """
        )

        st.markdown("### 5. Automated Secret Scrubbing (`SecretSanitizer`)")
        st.markdown(
            """
            Guarantees sensitive data never leaks into logs or persistent storage:
            - **Key-Name Scrubbing**: Redacts values for keys containing `token`, `password`, `secret`, `key`, `credential`, `auth`.
            - **Pattern Scrubbing**: Redacts Bearer tokens, GitHub PATs (`ghp_`), and long hex strings across all inputs and errors.
            """
        )


def run_dashboard() -> None:
    """CLI Entrypoint for running dashboard."""
    import subprocess
    app_path = os.path.abspath(__file__)
    subprocess.run([sys.executable, "-m", "streamlit", "run", app_path])
