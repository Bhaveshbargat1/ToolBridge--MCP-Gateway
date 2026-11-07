"""Secret sanitizer for masking credentials, tokens, and keys in logs and payloads."""
from __future__ import annotations

import json
import re
from typing import Any

# Sensitive dictionary key patterns to mask
_SENSITIVE_KEY_PATTERNS = re.compile(
    r"(token|password|secret|key|auth|credential|api_key|access_token|private_key)",
    re.IGNORECASE,
)

# Standard token regex patterns
_BEARER_PATTERN = re.compile(r"Bearer\s+([a-zA-Z0-9_\-\.]{10,})", re.IGNORECASE)
_GITHUB_TOKEN_PATTERN = re.compile(r"gh[pousr]_[a-zA-Z0-9_]{36,}")


class SecretSanitizer:
    """Scrubs passwords, API keys, and bearer tokens from data before logging."""

    @classmethod
    def sanitize(cls, data: Any) -> Any:
        """Recursively redact sensitive fields from dictionaries, lists, or strings."""
        if isinstance(data, dict):
            sanitized_dict = {}
            for k, v in data.items():
                if _SENSITIVE_KEY_PATTERNS.search(str(k)):
                    sanitized_dict[k] = "[REDACTED]"
                else:
                    sanitized_dict[k] = cls.sanitize(v)
            return sanitized_dict
        elif isinstance(data, list):
            return [cls.sanitize(item) for item in data]
        elif isinstance(data, str):
            masked = _BEARER_PATTERN.sub("Bearer [REDACTED]", data)
            masked = _GITHUB_TOKEN_PATTERN.sub("ghp_[REDACTED]", masked)
            return masked
        return data

    @classmethod
    def to_sanitized_json(cls, data: Any) -> str:
        """Convert data to a sanitized JSON string."""
        try:
            cleaned = cls.sanitize(data)
            return json.dumps(cleaned, default=str)
        except Exception:
            return '{"error": "Failed to serialize arguments"}'
