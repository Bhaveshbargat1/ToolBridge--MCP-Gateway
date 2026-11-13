"""Integration tests for ToolBridge Assistant FastAPI routes."""
import os
import pytest
from httpx import ASGITransport, AsyncClient

from toolbridge.api.app import create_app
from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.db.session import init_db
from toolbridge.models.server import UpstreamServerConfig
from toolbridge.models.tool import NamespacedTool
from toolbridge.security.rate_limiter import SlidingWindowRateLimiter

ADMIN_KEY = "test_admin_key_32_characters_long_toolbridge_sec"
OPERATOR_KEY = "test_operator_key_32_chars_long_toolbridge_sec"
READONLY_KEY = "test_readonly_key_32_chars_long_toolbridge_sec"


@pytest.fixture
async def assistant_api_client(tmp_path):
    os.environ["TOOLBRIDGE_ADMIN_KEY"] = ADMIN_KEY
    os.environ["TOOLBRIDGE_OPERATOR_KEY"] = OPERATOR_KEY
    os.environ["TOOLBRIDGE_READONLY_KEY"] = READONLY_KEY
    os.environ["TOOLBRIDGE_ASSISTANT_ENABLED"] = "true"
    os.environ["TOOLBRIDGE_ASSISTANT_PROVIDER"] = "mock"

    db_file = tmp_path / "assistant_test.db"
    os.environ["TOOLBRIDGE_SQLITE_URL"] = f"sqlite+aiosqlite:///{db_file}"
    await init_db()

    registry = ServerRegistry()
    await registry.register_server(UpstreamServerConfig(id="filesystem", name="Filesystem"))
    await registry.register_tools(
        "filesystem",
        [
            NamespacedTool(
                server_id="filesystem",
                original_name="read_file",
                namespaced_name="filesystem__read_file",
                description="Read safe file",
            ),
            NamespacedTool(
                server_id="filesystem",
                original_name="write_file",
                namespaced_name="filesystem__write_file",
                description="Write sensitive file",
            ),
        ],
    )

    manager = MCPClientManager(registry=registry)
    limiter = SlidingWindowRateLimiter(max_requests_per_minute=20)
    app = create_app(registry=registry, client_manager=manager, rate_limiter=limiter)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.asyncio
async def test_assistant_status_endpoint_auth(assistant_api_client):
    # Missing credentials -> 401
    resp = await assistant_api_client.get("/api/v1/assistant/status")
    assert resp.status_code == 401

    # Readonly credentials -> 200 OK
    resp = await assistant_api_client.get(
        "/api/v1/assistant/status",
        headers={"X-API-Key": READONLY_KEY},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is True
    assert data["status"] == "CONFIGURED"
    assert data["provider_name"] == "mock"


@pytest.mark.asyncio
async def test_assistant_chat_role_gating(assistant_api_client):
    payload = {"query": "What tools are available?"}

    # Missing credentials -> 401
    resp = await assistant_api_client.post("/api/v1/assistant/chat", json=payload)
    assert resp.status_code == 401

    # Readonly role -> 403 Forbidden (requires minimum OPERATOR)
    resp = await assistant_api_client.post(
        "/api/v1/assistant/chat",
        headers={"X-API-Key": READONLY_KEY},
        json=payload,
    )
    assert resp.status_code == 403
    assert "requires minimum role 'operator'" in resp.json()["detail"].lower()

    # Operator role -> 200 OK
    resp = await assistant_api_client.post(
        "/api/v1/assistant/chat",
        headers={"X-API-Key": OPERATOR_KEY},
        json=payload,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "answer" in data
    assert len(data["sources"]) > 0
    assert data["provider_status"] == "CONFIGURED"


@pytest.mark.asyncio
async def test_assistant_action_execution_auth_and_confirmation(assistant_api_client):
    action_payload = {
        "action_id": "act_nonexistent_123",
        "confirmed_by_admin": False,
    }

    # Operator role -> 403 Forbidden (requires ADMIN)
    resp = await assistant_api_client.post(
        "/api/v1/assistant/actions/execute",
        headers={"X-API-Key": OPERATOR_KEY},
        json=action_payload,
    )
    assert resp.status_code == 403

    # Admin role but confirmed_by_admin=False -> 400 Bad Request
    resp = await assistant_api_client.post(
        "/api/v1/assistant/actions/execute",
        headers={"X-API-Key": ADMIN_KEY},
        json=action_payload,
    )
    assert resp.status_code == 400
    assert "confirmation checkbox is required" in resp.json()["detail"].lower()

    # Admin role with confirmed=True but non-existent action -> 404
    action_payload["confirmed_by_admin"] = True
    resp = await assistant_api_client.post(
        "/api/v1/assistant/actions/execute",
        headers={"X-API-Key": ADMIN_KEY},
        json=action_payload,
    )
    assert resp.status_code == 404
