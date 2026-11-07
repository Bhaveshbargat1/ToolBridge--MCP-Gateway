"""Unit tests for PolicyEngine and role-based tool authorization."""
import pytest
from toolbridge.security.policy import PolicyEngine, SensitivityTier, UserRole


@pytest.mark.unit
def test_tool_sensitivity_classification():
    """Verify safe vs sensitive classification of tools."""
    assert PolicyEngine.get_tool_sensitivity("filesystem__read_file") == SensitivityTier.SAFE
    assert PolicyEngine.get_tool_sensitivity("filesystem__list_directory") == SensitivityTier.SAFE
    assert PolicyEngine.get_tool_sensitivity("postgres__execute_query") == SensitivityTier.SAFE
    assert PolicyEngine.get_tool_sensitivity("github__get_repository") == SensitivityTier.SAFE

    # Mutating tool
    assert PolicyEngine.get_tool_sensitivity("filesystem__write_file") == SensitivityTier.SENSITIVE
    # Unknown tool defaults to SENSITIVE for safety
    assert PolicyEngine.get_tool_sensitivity("custom__delete_database") == SensitivityTier.SENSITIVE


@pytest.mark.unit
def test_admin_and_operator_authorization():
    """Verify Admin and Operator can execute both SAFE and SENSITIVE tools."""
    # Admin
    ok, _ = PolicyEngine.is_authorized(UserRole.ADMIN, "filesystem__read_file")
    assert ok is True
    ok, _ = PolicyEngine.is_authorized(UserRole.ADMIN, "filesystem__write_file")
    assert ok is True

    # Operator
    ok, _ = PolicyEngine.is_authorized(UserRole.OPERATOR, "filesystem__read_file")
    assert ok is True
    ok, _ = PolicyEngine.is_authorized(UserRole.OPERATOR, "filesystem__write_file")
    assert ok is True


@pytest.mark.unit
def test_readonly_user_authorization():
    """Verify Readonly user is permitted for SAFE tools but denied for SENSITIVE tools."""
    # Permitted for SAFE
    ok, _ = PolicyEngine.is_authorized(UserRole.READONLY, "filesystem__read_file")
    assert ok is True
    ok, _ = PolicyEngine.is_authorized(UserRole.READONLY, "postgres__execute_query")
    assert ok is True

    # Denied for SENSITIVE
    ok, reason = PolicyEngine.is_authorized(UserRole.READONLY, "filesystem__write_file")
    assert ok is False
    assert "Permission Denied" in reason
    assert "SENSITIVE" in reason
