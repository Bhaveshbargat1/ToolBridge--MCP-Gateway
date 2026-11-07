"""API Key Authentication and Role-Based Authorization for FastAPI."""
from __future__ import annotations

import os
from typing import NamedTuple
from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials

from toolbridge.security.policy import UserRole

# Standard Header extraction
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_auth = HTTPBearer(auto_error=False)


class AuthenticatedUser(NamedTuple):
    """Holds identity and assigned role of an authenticated caller."""
    caller_id: str
    role: UserRole


def _get_configured_api_keys() -> dict[str, AuthenticatedUser]:
    """Retrieve API key mapping from environment or development defaults."""
    admin_key = os.environ.get("TOOLBRIDGE_ADMIN_KEY", "tb-admin-key-999")
    operator_key = os.environ.get("TOOLBRIDGE_OPERATOR_KEY", "tb-operator-key-555")
    readonly_key = os.environ.get("TOOLBRIDGE_READONLY_KEY", "tb-readonly-key-111")

    return {
        admin_key: AuthenticatedUser(caller_id="admin_user", role=UserRole.ADMIN),
        operator_key: AuthenticatedUser(caller_id="operator_user", role=UserRole.OPERATOR),
        readonly_key: AuthenticatedUser(caller_id="readonly_user", role=UserRole.READONLY),
    }


async def get_current_user(
    api_key: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_auth),
) -> AuthenticatedUser:
    """Validate API Key from 'X-API-Key' header or 'Authorization: Bearer' header."""
    token = api_key or (bearer.credentials if bearer else None)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials. Provide 'X-API-Key' or 'Authorization: Bearer <key>'.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    keys = _get_configured_api_keys()
    user = keys.get(token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key. Access denied.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return user


def require_role(min_role: UserRole):
    """Enforce minimum role requirement (ADMIN > OPERATOR > READONLY)."""
    role_weights = {
        UserRole.READONLY: 1,
        UserRole.OPERATOR: 2,
        UserRole.ADMIN: 3,
    }

    async def role_checker(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        user_weight = role_weights.get(user.role, 0)
        required_weight = role_weights.get(min_role, 3)

        if user_weight < required_weight:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Action requires minimum role '{min_role.value}', but caller has '{user.role.value}'.",
            )
        return user

    return role_checker
