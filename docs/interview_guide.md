# ToolBridge Enterprise MCP Gateway: Technical Interview Defense Guide

This guide contains deep technical questions and detailed answers based directly on the actual architecture and code implemented in **ToolBridge**. It is designed to prepare software engineers and architects to defend every design decision, protocol detail, and security guardrail in technical interviews.

---

## Section 1: Model Context Protocol (MCP) Architecture

### Q1: Why did you use `mcp.server.lowlevel.Server` instead of the higher-level `FastMCP` class for the gateway?
**Answer:**
`FastMCP` in the official Python SDK relies on static Python function decorators (`@mcp.tool()`). With `FastMCP`, tool names, signatures, and docstrings must be statically defined at import time.

A true enterprise MCP Gateway, however, operates as a **dynamic multiplexer**:
1. At boot time, it does not know what tools exist; it connects to arbitrary upstream servers (Filesystem, PostgreSQL, GitHub) and dynamically requests `tools/list`.
2. Upstream tools arrive with dynamic JSON schemas at runtime.
3. The gateway must expose an aggregated tool catalog and dispatch calls without having a static Python function declared for every upstream tool.

`mcp.server.lowlevel.Server` provides low-level protocol handler callbacks:
- `on_list_tools`: Dynamically queries the `ServerRegistry` and returns the aggregated list of `Tool` objects converted into MCP SDK types.
- `on_call_tool`: Intercepts any incoming `CallToolRequestParams`, extracts the namespaced tool name, routes it through pre-flight security guards and validation, and proxies it to the respective upstream client session.

### Q2: How does the Gateway multiplex upstream servers over `stdio` without stream conflicts?
**Answer:**
Over the `stdio` transport, standard output (`stdout`) is strictly reserved for JSON-RPC 2.0 protocol frames. Any unexpected text (such as Python `print()` statements or unhandled log messages) written to `stdout` corrupts the protocol framing and causes downstream clients (such as Claude Desktop or Cursor) to disconnect.

ToolBridge handles this using three architectural rules:
1. **Separation of Streams**: Downstream client communicates with ToolBridge over ToolBridge's own `sys.stdin` and `sys.stdout`. All ToolBridge internal logging is routed exclusively to `sys.stderr`.
2. **Isolated Subprocesses**: Each upstream server runs in its own dedicated child process spawned via `asyncio.create_subprocess_exec` using `mcp.client.stdio.stdio_client`. The child process's standard input and output are piped through individual OS pipes managed by `StdioServerParameters`.
3. **Async Lifecycle with `AsyncExitStack`**: In `MCPClientManager`, all client sessions and sub-process streams are registered within a centralized `AsyncExitStack`. If any upstream process terminates or the gateway shuts down, streams are closed gracefully in reverse order without dangling zombie processes.

---

## Section 2: Namespace Resolution & Tool Routing

### Q3: How does ToolBridge resolve tool naming collisions across disparate upstream servers?
**Answer:**
When multiple upstream servers expose tools with identical names (e.g., both a GitHub server and a GitLab server exposing `search_repositories`, or a Filesystem server and an S3 server exposing `read_file`), a collision would cause non-deterministic execution.

ToolBridge solves this at the discovery layer in `ToolDiscoveryEngine`:
1. **Deterministic Delimiter**: When `tools/list` is received from an upstream server with ID `server_id`, every tool name is transformed into `<server_id>__<tool_name>` (e.g., `filesystem__read_file`, `postgres__execute_query`).
2. **Original Schema Preservation**: The `NamespacedTool` model preserves both the namespaced name, the `original_name`, the `server_id`, the full input JSON schema, and description.
3. **Dispatch Demultiplexing**: In `ToolRouter.dispatch()`, incoming requests are split on the double-underscore delimiter (`__`). The router looks up the server ID in `ServerRegistry`, verifies the server is connected, unwraps the arguments, and issues `session.call_tool(original_name, arguments)` to the targeted upstream client session.

### Q4: What happens if an upstream server crashes, times out, or returns invalid data?
**Answer:**
ToolBridge implements strict fault isolation:
1. **Isolated Upstream Failure**: If the PostgreSQL upstream crashes, its `ServerStatus` transitions to `ERROR`. The `ServerRegistry` updates its heartbeat and error message, but the Gateway remains operational for `filesystem` and `github` tools.
2. **Schema Pre-flight Validation**: Before passing arguments to an upstream server, `ToolRouter` validates the payload against the cached JSON schema using `jsonschema.validate()`. Malformed requests are rejected immediately at the gateway boundary with a structured error, saving upstream compute and network overhead.
3. **Error Wrapping**: If an upstream call times out or throws an exception, `ToolRouter` catches it and returns a standard `CallToolResult(is_error=True, content=[TextContent(type="text", text=f"Error: {e}")])`. The gateway process never crashes or drops its downstream connection due to an upstream failure.

---

## Section 3: Deep Security Engineering & Guardrails

### Q5: Describe the 7 defense layers implemented in `FilesystemGuard` to stop path traversal and unauthorized disk access.
**Answer:**
Untrusted LLMs frequently generate manipulative paths attempting to escape directory sandboxes (e.g. `../../etc/passwd`, absolute paths, symlinks, Windows device names). `FilesystemGuard` executes 7 distinct security checks:
1. **Null-Byte Injection Check**: Detects and rejects `\0` characters to prevent C-level string truncation vulnerabilities.
2. **Absolute Path Rejection**: Blocks paths starting with `/`, `\`, drive letters (`C:`), or UNC paths (`\\server\share`). All operations must specify relative paths within the sandbox.
3. **Multiple-Dots Traversal Check**: Detects patterns such as `.../` or `..../` which bypass simple `../` replacements in some operating systems.
4. **Canonical Path Resolution**: Uses `pathlib.Path.resolve()` to resolve all `.` and `..` segments to an absolute canonical path.
5. **Canonical Containment Verification**: Calls `resolved_path.relative_to(sandbox_root.resolve())`. If the resolved path does not reside strictly within the sandbox root directory, a `PathSecurityError` is raised.
6. **Symlink Escape Defense**: Resolves symlinks and ensures that the final link target also satisfies canonical containment.
7. **Windows Reserved Device Defense**: Specifically checks file and directory basenames against Windows reserved DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1` through `COM9`, `LPT1` through `LPT9`), preventing system lockups and unauthorized device interactions.

In addition, writes are conducted **atomically**: the guard writes to a unique `.tmp` file in the same directory and renames it atomically to the destination, ensuring no partial or corrupted files are read if an operation is interrupted.

### Q6: Why is regular expression parsing dangerous for SQL security, and how does `SQLSecurityGuard` solve this?
**Answer:**
Regex-based SQL filtering fails against real-world evasion techniques:
- Comments (`SELECT /*!50000 ... */`)
- Whitespace variations and newlines
- Hex/Unicode encodings
- Stacked queries disguised behind subqueries or CTEs (`WITH x AS (...)`)

`SQLSecurityGuard` implements Abstract Syntax Tree (AST) tokenization using `sqlparse`:
1. **Statement Splitting**: It parses the query into distinct statements. If more than 1 statement is present (e.g. `SELECT 1; DROP TABLE users;`), it immediately rejects the query to stop stacked query injection.
2. **AST Command Type Whitelisting**: It extracts the top-level token type and requires it to be strictly `SELECT`. Any statement beginning with `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, `GRANT`, `REVOKE`, or `EXEC` is rejected.
3. **Forbidden Clause Inspection**: The AST is traversed to detect `INTO` keywords (preventing `SELECT ... INTO OUTFILE` or table-creation commands).
4. **Dangerous Function Blacklisting**: Common dangerous database functions (such as `pg_sleep`, `pg_terminate_backend`, `dblink`, `version`) are blocked.
5. **Database-Level Defense-in-Depth**: Even if an attacker finds an AST bypass, the database connection pool runs with `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`, ensuring that PostgreSQL's own query planner rejects any mutation at the database engine level.

### Q7: Explain ToolBridge's Role-Based Access Control (RBAC) and Sensitivity Tiers.
**Answer:**
ToolBridge implements a two-dimensional authorization model:
1. **Sensitivity Tiers**: Every exposed tool is classified by `PolicyEngine` into either:
   - `SAFE`: Read-only queries, table inspections, file reading, directory listing.
   - `SENSITIVE`: Operations that alter state, overwrite files, or touch sensitive external systems (e.g. `filesystem__write_file`).
2. **User Roles**: Callers authenticate via API keys or Bearer tokens mapped to three roles:
   - `ADMIN`: Unrestricted execution across all tools and management endpoints.
   - `OPERATOR`: Permitted to execute all `SAFE` tools and approved `SENSITIVE` tools (e.g., workspace writes).
   - `READONLY`: Restricted strictly to `SAFE` tools. Any attempt to invoke a `SENSITIVE` tool immediately results in HTTP 403 Forbidden and an audit record marked `UNAUTHORIZED`.

### Q8: How does ToolBridge guarantee that API keys and passwords are not written to persistent logs?
**Answer:**
Logging raw tool arguments or error traces can violate SOC2, GDPR, and HIPAA compliance by storing credentials in plaintext on disk.

ToolBridge integrates `SecretSanitizer`:
1. **Recursive JSON Inspection**: Before arguments are persisted by `AuditService`, they pass through `SecretSanitizer.sanitize()`.
2. **Key-Name Inspection**: If an argument key contains words like `token`, `password`, `secret`, `key`, `credential`, `auth`, `authorization`, its value is replaced with `"***REDACTED***"`.
3. **Pattern Matching**: String values are scanned against regex patterns detecting GitHub tokens (`ghp_[a-zA-Z0-9]{36}`), Bearer tokens, and high-entropy API key patterns.
4. **Error Sanitization**: Server stack traces and exception messages are sanitized before being returned or logged.

---

## Section 4: Concurrency, Performance & Production Readiness

### Q9: What rate limiting algorithm is used, and what are its trade-offs?
**Answer:**
ToolBridge uses an in-memory `SlidingWindowRateLimiter`:
- **Algorithm**: It records timestamps of requests in a `collections.deque` per `caller_id`. When a new request arrives, timestamps older than `now - window_seconds` are evicted. If the queue length exceeds `max_requests`, the request is denied with HTTP 429 and a `Retry-After` header.
- **Trade-offs**:
  - *Advantage*: Very fast, no external network dependencies (no Redis required for single-node deployments), smooth rate limiting without boundary-reset spikes typical of fixed-window limiters.
  - *Limitation*: Memory is local to the Python process. If ToolBridge is scaled horizontally across multiple instances behind a load balancer, instances do not share rate limit state. In a multi-replica production environment, state should be backed by Redis or Dragonfly using a Redis Token Bucket script.

### Q10: If asked to deploy ToolBridge to production next week, what gaps would you honestly report to leadership?
**Answer:**
A credible senior engineer never claims a prototype is production-ready without thorough operational testing. The following gaps must be addressed:
1. **Distributed Rate Limiting**: Migrate from in-memory sliding window to a shared Redis cluster.
2. **PostgreSQL Upstream Provisioning**: The local PostgreSQL setup script requires superuser privileges to create the `mcp_readonly` user and database; production requires Infrastructure-as-Code (Terraform) and AWS Secrets Manager integration.
3. **Transport Protocol**: Downstream clients currently connect via `stdio` (ideal for Claude Desktop and local IDEs). For enterprise microservice architectures, an HTTP SSE (Server-Sent Events) or WebSocket transport with mTLS termination is required.
4. **Persistent Server Registry**: Server configurations are currently stored in-memory during gateway boot. In a multi-tenant enterprise environment, configurations should be persisted in PostgreSQL with automated migration scripts (Alembic).
5. **High Availability**: Multiple Gateway workers behind a reverse proxy (e.g., NGINX / Envoy) with health probes (`/health`) and graceful connection draining.
