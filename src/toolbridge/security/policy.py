"""Security and authorization policy engine for ToolBridge."""
from __future__ import annotations

from enum import Enum
import json
import logging
import os
from typing import Final

logger = logging.getLogger("toolbridge.security.policy")


class UserRole(str, Enum):
    """Management and invocation user roles."""
    ADMIN = "admin"
    OPERATOR = "operator"
    READONLY = "readonly"


class SensitivityTier(str, Enum):
    """Sensitivity classifications for MCP tools."""
    SAFE = "SAFE"            # Read-only, low-risk tools
    SENSITIVE = "SENSITIVE"  # Mutating, file-writing, or state-changing tools


# Default sensitivity classifications for known tools.
# Security Note on postgres__execute_query:
# While classified as SAFE from a SQL mutation perspective (DDL/DML mutations are strictly
# blocked by SQLSecurityGuard and database transaction read-only configuration), SELECT
# queries still represent a data-exfiltration vector if sensitive schemas/tables are accessible.
_SENSITIVITY_MAP: Final[dict[str, SensitivityTier]] = {
    # Filesystem
    "filesystem__read_file": SensitivityTier.SAFE,
    "filesystem__list_directory": SensitivityTier.SAFE,
    "filesystem__search_files": SensitivityTier.SAFE,
    "filesystem__get_file_info": SensitivityTier.SAFE,
    "filesystem__write_file": SensitivityTier.SENSITIVE,
    # Postgres
    "postgres__list_tables": SensitivityTier.SAFE,
    "postgres__describe_table": SensitivityTier.SAFE,
    "postgres__execute_query": SensitivityTier.SAFE,  # SAFE for mutation, but data-exfiltration risk
    # GitHub
    "github__get_repository": SensitivityTier.SAFE,
    "github__list_issues": SensitivityTier.SAFE,
    "github__search_repositories": SensitivityTier.SAFE,
}


def _get_role_allowlists() -> dict[str, set[str]]:
    """Load optional config-driven per-role allowlists from TOOLBRIDGE_ROLE_ALLOWLIST env var (JSON)."""
    raw = os.environ.get("TOOLBRIDGE_ROLE_ALLOWLIST", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return {k.lower(): set(v) for k, v in data.items() if isinstance(v, list)}
    except Exception as e:
        logger.warning(f"Failed to parse TOOLBRIDGE_ROLE_ALLOWLIST: {e}")
        return {}


class PolicyEngine:
    """Enforces user role authorization and tool sensitivity policies."""

    @staticmethod
    def get_tool_sensitivity(tool_name: str) -> SensitivityTier:
        """Classify tool sensitivity. Default is SENSITIVE if unknown to be safe."""
        return _SENSITIVITY_MAP.get(tool_name, SensitivityTier.SENSITIVE)

    @classmethod
    def is_authorized(cls, role: UserRole | str, tool_name: str) -> tuple[bool, str]:
        """Check whether a user role is permitted to invoke a tool.

        Rules:
        - ADMIN: Permitted for all tools (unless explicitly restricted by role allowlist).
        - OPERATOR: Permitted for SAFE and SENSITIVE tools.
        - READONLY: Permitted ONLY for SAFE tools.
        - Optional config-driven allowlists (TOOLBRIDGE_ROLE_ALLOWLIST) override defaults.

        Returns:
            Tuple of (is_allowed: bool, reason: str).
        """
        role_val = (role.value if hasattr(role, "value") else str(role)).lower()
        tier = cls.get_tool_sensitivity(tool_name)

        # Check optional config-driven per-role allowlist first
        allowlists = _get_role_allowlists()
        if role_val in allowlists:
            role_allowed = allowlists[role_val]
            server_id = tool_name.split("__", 1)[0] if "__" in tool_name else ""
            if tool_name not in role_allowed and server_id not in role_allowed and "*" not in role_allowed:
                return False, f"Permission Denied: Tool '{tool_name}' is not in the configured allowlist for role '{role_val}'."

        if role_val == UserRole.ADMIN.value:
            return True, "Authorized as Admin."
        elif role_val == UserRole.OPERATOR.value:
            return True, "Authorized as Operator."
        elif role_val == UserRole.READONLY.value:
            if tier == SensitivityTier.SAFE:
                return True, "Authorized for safe read-only tool."
            else:
                return False, f"Permission Denied: Role '{role_val}' is not authorized to execute SENSITIVE tool '{tool_name}'."
        else:
            return False, f"Unauthorized: Unknown role '{role_val}'."
