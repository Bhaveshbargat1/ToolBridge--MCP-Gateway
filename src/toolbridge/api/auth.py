"""API Key Authentication and Role-Based Authorization for FastAPI."""
from __future__ import annotations

import hmac
import os
import re
from typing import Final, NamedTuple
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from toolbridge.security.policy import UserRole

# Standard Header extraction
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_auth = HTTPBearer(auto_error=False)

MIN_KEY_LENGTH: Final[int] = 32

KNOWN_INSECURE_PLACEHOLDERS: Final[set[str]] = {
    "tb-admin-key-999",
    "tb-operator-key-555",
    "tb-readonly-key-111",
    "change-this-to-a-strong-random-api-key-in-production",
    "changeme",
    "placeholder",
    "admin",
    "secret",
    "password",
    "replace_with_strong_key",
    "your-secret-key-here",
}


class AuthenticatedUser(NamedTuple):
    """Holds identity and assigned role of an authenticated caller."""
    caller_id: str
    role: UserRole


def validate_api_key(key_name: str, key_value: str | None) -> str:
    """Validate that an API key is present, >= 32 characters, and not a known placeholder."""
    if not key_value or not key_value.strip():
        raise ValueError(
            f"API Key '{key_name}' is not set. All role keys (ADMIN, OPERATOR, READONLY) "
            f"must be defined via environment variables with minimum 32 characters."
        )

    val = key_value.strip()
    val_lower = val.lower()

    if val_lower in KNOWN_INSECURE_PLACEHOLDERS:
        raise ValueError(
            f"API Key '{key_name}' matches a known insecure placeholder. Please generate a cryptographically strong key."
        )

    if re.search(r"^(tb-.*-key-\d+|change[-_]?this|changeme|placeholder|your[-_]?key|secret|password)", val_lower):
        raise ValueError(
            f"API Key '{key_name}' matches an insecure pattern. Please generate a cryptographically strong key."
        )

    if len(val) < MIN_KEY_LENGTH:
        raise ValueError(
            f"API Key '{key_name}' is too short ({len(val)} chars). Minimum length is {MIN_KEY_LENGTH} characters."
        )

    return val


_CACHE_ENV_TUPLE: tuple[str | None, str | None, str | None] | None = None
_CONFIGURED_KEYS_CACHE: dict[str, AuthenticatedUser] | None = None


def get_configured_api_keys() -> dict[str, AuthenticatedUser]:
    """Retrieve validated API key mapping from environment with fast cache check."""
    global _CACHE_ENV_TUPLE, _CONFIGURED_KEYS_CACHE
    current_env = (
        os.environ.get("TOOLBRIDGE_ADMIN_KEY"),
        os.environ.get("TOOLBRIDGE_OPERATOR_KEY"),
        os.environ.get("TOOLBRIDGE_READONLY_KEY"),
    )
    if _CONFIGURED_KEYS_CACHE is not None and _CACHE_ENV_TUPLE == current_env:
        return _CONFIGURED_KEYS_CACHE

    admin_key = validate_api_key("TOOLBRIDGE_ADMIN_KEY", current_env[0])
    operator_key = validate_api_key("TOOLBRIDGE_OPERATOR_KEY", current_env[1])
    readonly_key = validate_api_key("TOOLBRIDGE_READONLY_KEY", current_env[2])

    _CONFIGURED_KEYS_CACHE = {
        admin_key: AuthenticatedUser(caller_id="admin_user", role=UserRole.ADMIN),
        operator_key: AuthenticatedUser(caller_id="operator_user", role=UserRole.OPERATOR),
        readonly_key: AuthenticatedUser(caller_id="readonly_user", role=UserRole.READONLY),
    }
    _CACHE_ENV_TUPLE = current_env
    return _CONFIGURED_KEYS_CACHE


def _get_configured_api_keys() -> dict[str, AuthenticatedUser]:
    """Internal alias for backward compatibility."""
    return get_configured_api_keys()


async def get_current_user(
    api_key: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_auth),
) -> AuthenticatedUser:
    """Validate API Key from 'X-API-Key' header or 'Authorization: Bearer' header.

    Compares credentials in constant time with no early exit across candidates.
    """
    token = api_key or (bearer.credentials if bearer else None)

    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials. Provide 'X-API-Key' or 'Authorization: Bearer <key>'.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    try:
        keys = get_configured_api_keys()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Gateway Authentication Misconfigured: {e}",
        ) from e

    token_str = token.strip()
    matched_user: AuthenticatedUser | None = None

    # Constant-time comparison across all candidate keys with NO early exit
    for configured_key, user in keys.items():
        if hmac.compare_digest(token_str, configured_key):
            matched_user = user

    if matched_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key. Access denied.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return matched_user


def require_role(min_role: UserRole):
    """Enforce minimum role requirement (ADMIN > OPERATOR > READONLY)."""
    role_weights = {
        UserRole.READONLY: 1,
        UserRole.OPERATOR: 2,
        UserRole.ADMIN: 3,
    }

    async def role_checker(user: AuthenticatedUser = Security(get_current_user)) -> AuthenticatedUser:
        user_weight = role_weights.get(user.role, 0)
        required_weight = role_weights.get(min_role, 3)

        if user_weight < required_weight:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Action requires minimum role '{min_role.value}', but caller has '{user.role.value}'.",
            )
        return user

    return role_checker
