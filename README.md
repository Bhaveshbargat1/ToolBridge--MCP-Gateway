# ToolBridge: Enterprise Model Context Protocol (MCP) Gateway

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![MCP SDK v2](https://img.shields.io/badge/mcp--sdk-v2.3.0-green.svg)](https://modelcontextprotocol.io/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162.2-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.67.0-FF4B4B.svg)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/tests-180%20passed-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/Security-7--Layer%20Sandbox-red.svg)]()

> **ToolBridge** is a centralized, secure **Enterprise MCP Gateway** that connects multiple upstream Model Context Protocol (MCP) servers and multiplexes their tools to downstream AI applications (Claude Desktop, Cursor, IDEs, autonomous LLM agents) through a single, unified, namespaced MCP interface.

---

## 📑 Table of Contents

- [Architectural Overview](#-architectural-overview)
- [Key Features](#-key-features)
- [Security Guardrails & Defense-in-Depth](#-security-guardrails--defense-in-depth)
- [Prerequisites & Environment Setup](#-prerequisites--environment-setup)
- [Running the Gateway & Services](#-running-the-gateway--services)
  - [1. Downstream MCP Gateway (stdio)](#1-downstream-mcp-gateway-stdio)
  - [2. FastAPI Management & Audit API](#2-fastapi-management--audit-api)
  - [3. Streamlit Observability Dashboard](#3-streamlit-observability-dashboard)
- [Claude Desktop Integration](#-claude-desktop-integration)
- [End-to-End Demo Workflow](#-end-to-end-demo-workflow)
- [Test Suite & Quality Verification](#-test-suite--quality-verification)
- [Honest Production Readiness & Limitations](#-honest-production-readiness--limitations)
- [Technical Interview Defense Guide](#-technical-interview-defense-guide)

---

## 🏛️ Architectural Overview

ToolBridge simultaneously acts as:
1. **An MCP Client** to upstream servers (Filesystem, PostgreSQL, GitHub) via isolated asynchronous subprocesses over standard IO (`stdio`).
2. **An MCP Server** to downstream AI clients exposing a unified, aggregated, namespaced tool catalog.

```mermaid
flowchart TD
    subgraph DownstreamClients ["Downstream AI Clients"]
        Claude["Claude Desktop"]
        Cursor["Cursor IDE"]
        Agent["Autonomous LLM Agents"]
    end

    subgraph ToolBridge ["ToolBridge Enterprise Gateway"]
        DownstreamServer["Downstream Gateway Server<br/>(mcp.server.lowlevel.Server)"]
        Router["Dynamic Tool Router & Dispatcher"]
        Guard["Security & Guardrails Engine"]
        Policy["PolicyEngine (RBAC: Admin / Operator / Readonly)"]
        Limiter["Sliding Window Rate Limiter"]
        Sanitizer["Secret Sanitizer (***REDACTED***)"]
        Registry["Server Registry & Tool Catalog"]
        ClientMgr["MCP Client Manager (AsyncExitStack)"]
        AuditDB[("SQLite Audit Store<br/>(toolbridge.db)")]
        FastAPIApp["FastAPI Management API<br/>(Port 8000)"]
        Dashboard["Streamlit Control Plane<br/>(Port 8501)"]
    end

    subgraph Upstreams ["Controlled Upstream MCP Servers"]
        FS["Filesystem MCP Server<br/>(7-Layer Sandbox)"]
        PG["PostgreSQL MCP Server<br/>(AST Read-Only Pool)"]
        GH["GitHub MCP Server<br/>(REST API Proxy)"]
    end

    Claude -->|stdio / JSON-RPC| DownstreamServer
    Cursor -->|stdio / JSON-RPC| DownstreamServer
    Agent -->|HTTP / JSON-RPC| FastAPIApp

    DownstreamServer --> Router
    FastAPIApp --> Router
    Router --> Guard
    Guard --> Policy
    Guard --> Limiter
    Guard --> Sanitizer
    Router --> ClientMgr
    Sanitizer --> AuditDB
    FastAPIApp --> Registry
    Dashboard --> FastAPIApp
    Dashboard --> AuditDB

    ClientMgr -->|stdio subprocess| FS
    ClientMgr -->|stdio subprocess| PG
    ClientMgr -->|stdio subprocess| GH
```

---

## 🌟 Key Features

- **Dynamic Tool Discovery**: Queries `tools/list` on all connected upstreams at boot time and registers dynamic JSON schemas at runtime.
- **Collision Prevention via Namespacing**: Re-maps upstream tools to `<server_id>__<tool_name>` (e.g. `filesystem__read_file`, `postgres__execute_query`, `github__list_issues`).
- **MCP Python SDK v2 Native**: Built strictly on official `mcp==2.3.0` using `mcp.server.lowlevel.Server` and `mcp.client.stdio.stdio_client`.
- **Pre-flight JSON Schema Validation**: Validates arguments against discovered schemas via `jsonschema` before passing payloads to upstreams.
- **Fault-Tolerant Concurrency**: Upstream failures, timeouts, and disconnects are cleanly trapped. The gateway never crashes if an upstream drops.
- **Full Observability & Control Plane**:
  - FastAPI management service with RBAC (`ADMIN`, `OPERATOR`, `READONLY`).
  - Interactive Streamlit dashboard with tool runner, live audit logs, and metrics.
  - Secret scrubbing redacting tokens and passwords before writing to SQLite.

---

## 🛡️ Security Guardrails & Defense-in-Depth

### 1. Filesystem Sandbox (`FilesystemGuard`)
Guards file access within an isolated workspace directory (`./workspace_sandbox`):
- **Null-Byte Rejection**: Detects `\0` bytes to block C string truncation attacks.
- **Absolute Path Prohibition**: Blocks `/etc/passwd`, `C:\Windows`, UNC shares (`\\server\share`).
- **Multiple Dots Neutralization**: Rejects `.../` traversal patterns.
- **Canonical Containment**: Verifies `resolved_path.relative_to(sandbox_root.resolve())`.
- **Symlink Escape Defense**: Asserts symlink targets resolve within the sandbox.
- **Windows Device Name Defense**: Blocks reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
- **Atomic Writes**: Writes to `.tmp` files and atomically replaces target files to prevent partial corruptions.

### 2. SQL AST Inspection (`SQLSecurityGuard`)
Guards database queries with Abstract Syntax Tree parsing (`sqlparse`):
- **Whitelist Enforcement**: Permitted command type is strictly `SELECT`. Rejects `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`.
- **Stacked Query Defense**: Prevents multi-statement attacks (`SELECT 1; DROP TABLE users;`).
- **Dangerous Clause Rejection**: Blocks table-creation attempts (`SELECT ... INTO`).
- **Dangerous Function Blacklist**: Blocks functions such as `pg_sleep`, `pg_terminate_backend`, `dblink`.
- **Read-Only Transaction Isolation**: Database connection pool executes under `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`.

### 3. Role-Based Access Control (`PolicyEngine`)
- **Tiers**: Categorizes tools into `SAFE` (read-only) and `SENSITIVE` (state mutations like `filesystem__write_file`).
- **Roles**:
  - `ADMIN`: Full access to all tools and configuration endpoints.
  - `OPERATOR`: Safe operations + sensitive file writes.
  - `READONLY`: Strictly read-only operations. Sensitive calls trigger HTTP 403 Forbidden.

### 4. Secret Sanitization (`SecretSanitizer`)
Automatically masks passwords, GitHub Personal Access Tokens (`ghp_`), Bearer tokens, and sensitive keys with `***REDACTED***` in audit logs and error messages.

---

## 🚀 Prerequisites & Environment Setup

### Prerequisites
- **Python 3.12+** (tested on Python 3.12.10)
- **Git**
- Optional: PostgreSQL 14+ (or use the built-in SQLite database backend for local zero-dependency testing)

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-org/toolbridge.git
   cd toolbridge
   ```

2. **Create and activate virtual environment**:
   ```powershell
   # Windows PowerShell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3.12 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -e ".[all,dev]"
   ```

4. **Configure environment variables & API keys**:
   ```bash
   cp .env.example .env
   ```
   Generate strong, cryptographically secure keys (minimum 32 characters) for each role:
   ```bash
   python -c "import secrets; print('TOOLBRIDGE_ADMIN_KEY=' + secrets.token_urlsafe(32))"
   python -c "import secrets; print('TOOLBRIDGE_OPERATOR_KEY=' + secrets.token_urlsafe(32))"
   python -c "import secrets; print('TOOLBRIDGE_READONLY_KEY=' + secrets.token_urlsafe(32))"
   ```
   Add these generated keys to your `.env` file. The API will refuse to boot if any key is missing, shorter than 32 characters, or set to a known placeholder.

---

## 💻 Running the Gateway & Services

### 1. Downstream MCP Gateway (`stdio`)
To run ToolBridge as a stdio server for Claude Desktop, Cursor, or AI agent processes:
```bash
python -m toolbridge.server.gateway
# Or via launcher:
python run_demo.py gateway
```
*Note: All gateway logging and banners are piped strictly to `stderr` so the standard input/output stream remains 100% pure JSON-RPC 2.0 without protocol corruption.*

### 2. FastAPI Management & Audit API
Run the REST API management service:
```bash
uvicorn toolbridge.api.app:app --host 127.0.0.1 --port 8000
# Or via launcher:
python run_demo.py api
```
Interactive Swagger API documentation is available at:
👉 **`http://127.0.0.1:8000/docs`**

**API Authentication Roles:**
- Admin (`TOOLBRIDGE_ADMIN_KEY`): Server registration, dynamic configurations, audit log access, all tool invocations.
- Operator (`TOOLBRIDGE_OPERATOR_KEY`): Safe operations + sensitive tool execution (`filesystem__write_file`).
- Read-Only (`TOOLBRIDGE_READONLY_KEY`): Strictly read-only operations (`filesystem__read_file`, `postgres__execute_query`).

### 3. Streamlit Observability Dashboard
Launch the control plane and interactive tool execution UI:
```bash
python run_demo.py dashboard
```
Dashboard opens in your browser at:
👉 **`http://127.0.0.1:8501`** (Protected by Admin API Key Gate)

---

## 🤖 Claude Desktop Integration

To expose all ToolBridge upstream tools (Filesystem, PostgreSQL, GitHub) to **Claude Desktop**, add the following configuration to your `claude_desktop_config.json`:

**Windows Path:** `%APPDATA%\Claude\claude_desktop_config.json`  
**macOS Path:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "toolbridge": {
      "command": "<absolute-path-to-toolbridge-repo>/.venv/Scripts/python.exe",
      "args": [
        "-m",
        "toolbridge.server.gateway"
      ],
      "env": {
        "FILESYSTEM_SANDBOX_ROOT": "<absolute-path-to-toolbridge-repo>/workspace_sandbox",
        "TOOLBRIDGE_STDIO_ROLE": "readonly",
        "GITHUB_PERSONAL_ACCESS_TOKEN": ""
      }
    }
  }
}
```
> [!NOTE]
> Replace `<absolute-path-to-toolbridge-repo>` with the absolute path to your cloned ToolBridge repository. If `FILESYSTEM_SANDBOX_ROOT` is relative, ToolBridge automatically anchors it to the project root directory.

Restart Claude Desktop, and click the hammer icon 🔨 to verify that all namespaced tools appear automatically!

---

## 🧪 End-to-End Demo Workflow

### 1. Check Gateway Health
```bash
curl -X GET "http://127.0.0.1:8000/health"
```
**Response:**
```json
{
  "status": "healthy",
  "gateway": "ToolBridge Enterprise Gateway",
  "version": "0.1.0",
  "uptime_seconds": 12.4
}
```

### 2. Discover Namespaced Tools
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/tools" \
     -H "X-API-Key: YOUR_READONLY_KEY_HERE"
```
**Response (Sample):**
```json
{
  "total": 11,
  "tools": [
    {
      "namespaced_name": "filesystem__read_file",
      "server_id": "filesystem",
      "sensitivity_tier": "safe",
      "description": "Read file contents securely within designated workspace."
    },
    {
      "namespaced_name": "filesystem__write_file",
      "server_id": "filesystem",
      "sensitivity_tier": "sensitive",
      "description": "Atomically write or overwrite a file inside the designated sandbox."
    },
    {
      "namespaced_name": "postgres__execute_query",
      "server_id": "postgres",
      "sensitivity_tier": "safe",
      "description": "Execute an approved read-only SELECT query against PostgreSQL with AST validation."
    }
  ]
}
```

### 3. Invoke Tool: Read-Only Query (Success)
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/tools/invoke" \
     -H "X-API-Key: YOUR_READONLY_KEY_HERE" \
     -H "Content-Type: application/json" \
     -d '{
       "tool_name": "filesystem__list_directory",
       "arguments": {"path": ""}
     }'
```

### 4. Security Test: Sensitive Tool Attempt by Read-Only User (Blocked by RBAC)
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/tools/invoke" \
     -H "X-API-Key: YOUR_READONLY_KEY_HERE" \
     -H "Content-Type: application/json" \
     -d '{
       "tool_name": "filesystem__write_file",
       "arguments": {"path": "test.txt", "content": "attack"}
     }'
```
**Response:**
```json
{
  "detail": "Role 'readonly' is not permitted to execute sensitive tool 'filesystem__write_file'."
}
```
*(HTTP Status: `403 Forbidden` — an audit record is logged with status `UNAUTHORIZED`).*

### 5. Security Test: SQL Injection Blocked by AST Guard
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/tools/invoke" \
     -H "X-API-Key: YOUR_ADMIN_KEY_HERE" \
     -H "Content-Type: application/json" \
     -d '{
       "tool_name": "postgres__execute_query",
       "arguments": {"query": "SELECT * FROM users; DROP TABLE logs;"}
     }'
```
**Response:**
```json
{
  "detail": "SQLSecurityError: Multi-statement execution is strictly prohibited. Exactly one query is permitted."
}
```

---

## 🔬 Test Suite & Quality Verification

ToolBridge includes a comprehensive automated test suite consisting of unit tests, security penetration tests, and end-to-end integration tests using separate downstream MCP clients.

Run the full test suite:
```powershell
.\.venv\Scripts\pytest -v
```

**Test Summary:**
```text
======================= 180 passed in 66.34s =======================
```
*(All 180 tests pass with 0 skipped; symlink validation tests include mock fallbacks for non-elevated developer mode environments).*

---

## ⚠️ Honest Production Readiness & Limitations

To maintain professional engineering integrity, the following architectural boundaries should be noted:

1. **Single-Node Deployment & In-Memory Rate Limiting**: The current `SlidingWindowRateLimiter` operates in-memory on a single Python process with automatic key eviction to bound memory. If ToolBridge is scaled horizontally behind a round-robin load balancer, rate limits are not shared across nodes. Multi-node clusters require a distributed Redis token-bucket implementation.
2. **Dashboard Direct Database Access**: The Streamlit dashboard connects directly to the local SQLite database (`toolbridge.db`) for real-time audit visualization, bypassing REST API RBAC middleware. An Admin Key authentication gate is enforced in the dashboard UI to restrict access to sensitive execution and audit tabs.
3. **PostgreSQL Setup Script**: The provided `scripts/setup_postgres_db.sql` creates a locked-down `mcp_readonly` role with `SET default_transaction_read_only = on` and explicit SELECT grants. In enterprise production, credentials should be dynamically rotated via AWS Secrets Manager or HashiCorp Vault.
4. **Transport Protocols**: Downstream AI clients currently connect via `stdio` (Claude Desktop / Cursor) or the HTTP management API. High-concurrency agent workflows would benefit from an SSE (Server-Sent Events) transport with mTLS termination.

---

## 📚 Technical Interview Defense Guide

For comprehensive interview preparation covering the low-level MCP protocol, async multiplexing, AST SQL tokenization, and filesystem containment proofs, refer to:
👉 **[`docs/interview_guide.md`](docs/interview_guide.md)**
