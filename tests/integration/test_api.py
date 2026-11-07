"""Integration tests for ToolBridge FastAPI Management API."""
import asyncio
import os
import sys
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from toolbridge.api.app import create_app
from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.db.session import init_db
from toolbridge.models.server import TransportType, UpstreamServerConfig
from toolbridge.security.rate_limiter import SlidingWindowRateLimiter

ADMIN_KEY = "tb-admin-key-999"
OPERATOR_KEY = "tb-operator-key-555"
READONLY_KEY = "tb-readonly-key-111"


@pytest.fixture
async def api_client(tmp_path: Path):
    """Setup test FastAPI app with in-memory SQLite and isolated sandbox."""
    db_file = tmp_path / "api_test.db"
    os.environ["TOOLBRIDGE_SQLITE_URL"] = f"sqlite+aiosqlite:///{db_file}"
    await init_db()

    sandbox = tmp_path / "api_sandbox"
    sandbox.mkdir()
    (sandbox / "api_welcome.txt").write_text("Hello from API test file!", encoding="utf-8")

    registry = ServerRegistry()
    # Register Filesystem
    await registry.register_server(UpstreamServerConfig(
        id="filesystem",
        name="Filesystem Server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.filesystem.server"],
        env={"FILESYSTEM_SANDBOX_ROOT": str(sandbox)},
    ))

    manager = MCPClientManager(registry=registry)
    await manager.connect_all()

    # Create app with low rate limit for testing
    rate_limiter = SlidingWindowRateLimiter(max_requests_per_minute=10)
    app = create_app(registry=registry, client_manager=manager, rate_limiter=rate_limiter)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, registry, manager, sandbox

    await manager.disconnect_all()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_health_endpoint(api_client):
    """Verify public health endpoint returns 200 without authentication."""
    client, _, _, _ = api_client
    res = await client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["total_servers"] >= 1
    assert data["connected_servers"] >= 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_authentication_enforcement(api_client):
    """Verify missing or invalid API keys return 401 Unauthorized."""
    client, _, _, _ = api_client

    # 1. Missing header
    res_no_key = await client.get("/api/v1/servers")
    assert res_no_key.status_code == 401
    assert "Missing authentication" in res_no_key.json()["detail"]

    # 2. Invalid key
    res_bad_key = await client.get("/api/v1/servers", headers={"X-API-Key": "invalid-token"})
    assert res_bad_key.status_code == 401
    assert "Invalid API Key" in res_bad_key.json()["detail"]

    # 3. Valid key
    res_valid = await client.get("/api/v1/servers", headers={"X-API-Key": READONLY_KEY})
    assert res_valid.status_code == 200


@pytest.mark.integration
@pytest.mark.asyncio
async def test_role_authorization_for_server_management(api_client):
    """Verify only Admin can register and delete servers."""
    client, _, _, _ = api_client

    new_server_payload = {
        "id": "new_dummy_server",
        "name": "Dummy Server",
        "transport": "stdio",
        "command": sys.executable,
        "args": ["-c", "print('dummy')"],
    }

    # Readonly user cannot register server (Forbidden 403)
    res_readonly = await client.post(
        "/api/v1/servers",
        json=new_server_payload,
        headers={"X-API-Key": READONLY_KEY},
    )
    assert res_readonly.status_code == 403
    assert "Action requires minimum role 'admin'" in res_readonly.json()["detail"]

    # Admin user can register server (Created 201)
    res_admin = await client.post(
        "/api/v1/servers",
        json=new_server_payload,
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert res_admin.status_code == 201

    # Admin can delete server
    del_res = await client.delete(
        "/api/v1/servers/new_dummy_server",
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert del_res.status_code == 200


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tool_listing_and_sensitivity_classification(api_client):
    """Verify tool listing returns tools with correct sensitivity tiers."""
    client, _, _, _ = api_client
    res = await client.get("/api/v1/tools", headers={"X-API-Key": READONLY_KEY})
    assert res.status_code == 200

    data = res.json()
    assert data["total"] >= 5
    tools = {t["namespaced_name"]: t for t in data["tools"]}

    assert tools["filesystem__read_file"]["sensitivity_tier"] == "SAFE"
    assert tools["filesystem__write_file"]["sensitivity_tier"] == "SENSITIVE"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tool_invocation_authorization_and_audit(api_client):
    """Verify tool authorization, execution, and persistent audit logging."""
    client, _, _, sandbox = api_client

    # 1. Readonly user invoking SAFE tool -> 200 OK
    safe_invoke = await client.post(
        "/api/v1/tools/invoke",
        json={"tool_name": "filesystem__read_file", "arguments": {"path": "api_welcome.txt"}},
        headers={"X-API-Key": READONLY_KEY},
    )
    assert safe_invoke.status_code == 200
    assert safe_invoke.json()["status"] == "success"
    assert "Hello from API test file!" in safe_invoke.json()["result"]

    # 2. Readonly user invoking SENSITIVE tool -> 403 Forbidden
    denied_invoke = await client.post(
        "/api/v1/tools/invoke",
        json={
            "tool_name": "filesystem__write_file",
            "arguments": {"path": "unauthorized.txt", "content": "forbidden"},
        },
        headers={"X-API-Key": READONLY_KEY},
    )
    assert denied_invoke.status_code == 403
    assert "Permission Denied" in denied_invoke.json()["detail"]

    # 3. Admin user invoking SENSITIVE tool -> 200 OK
    admin_invoke = await client.post(
        "/api/v1/tools/invoke",
        json={
            "tool_name": "filesystem__write_file",
            "arguments": {"path": "admin_output.txt", "content": "Created by Admin via API"},
        },
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert admin_invoke.status_code == 200
    assert (sandbox / "admin_output.txt").exists()

    # 4. Verify Audit Logs recorded in SQLite
    audit_res = await client.get("/api/v1/audit", headers={"X-API-Key": OPERATOR_KEY})
    assert audit_res.status_code == 200
    logs = audit_res.json()["logs"]
    assert len(logs) >= 3

    # Check that UNAUTHORIZED status was logged
    unauth_logs = [l for l in logs if l["status"] == "UNAUTHORIZED"]
    assert len(unauth_logs) >= 1
    assert unauth_logs[0]["tool_name"] == "filesystem__write_file"
    assert unauth_logs[0]["caller_role"] == "readonly"

    # Check that SUCCESS status was logged
    success_logs = [l for l in logs if l["status"] == "SUCCESS"]
    assert len(success_logs) >= 2


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tool_invocation_schema_validation_error(api_client):
    """Verify invalid tool arguments return 400 Bad Request."""
    client, _, _, _ = api_client
    res = await client.post(
        "/api/v1/tools/invoke",
        json={"tool_name": "filesystem__read_file", "arguments": {}},  # Missing required 'path'
        headers={"X-API-Key": READONLY_KEY},
    )
    assert res.status_code == 400
    assert "Schema Validation Error" in res.json()["detail"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_rate_limiting_enforcement(api_client):
    """Verify rate limiter blocks callers exceeding quota with 429 Too Many Requests."""
    client, _, _, _ = api_client

    # Rate limiter configured with limit=10
    for _ in range(10):
        res = await client.post(
            "/api/v1/tools/invoke",
            json={"tool_name": "filesystem__read_file", "arguments": {"path": "api_welcome.txt"}},
            headers={"X-API-Key": ADMIN_KEY},
        )
        assert res.status_code == 200

    # 11th request exceeds quota
    exceeded_res = await client.post(
        "/api/v1/tools/invoke",
        json={"tool_name": "filesystem__read_file", "arguments": {"path": "api_welcome.txt"}},
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert exceeded_res.status_code == 429
    assert "Rate limit exceeded" in exceeded_res.json()["detail"]
    assert "Retry-After" in exceeded_res.headers
