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
_GITHUB_CLASSIC_PATTERN = re.compile(r"gh[pousr]_[a-zA-Z0-9_]{16,}")
_GITHUB_PAT_PATTERN = re.compile(r"github_pat_[a-zA-Z0-9_]{20,}")
_AI_KEY_PATTERN = re.compile(r"sk-(?:proj-|ant-)?[a-zA-Z0-9_\-]{20,}")
_AWS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")
_DSN_PASSWORD_PATTERN = re.compile(r"([a-zA-Z0-9+_-]+://[^:\s@]+:)(.+?)(@(?:[a-zA-Z0-9._-]+)(?::\d+)?(?:/|$))")


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
            masked = _GITHUB_CLASSIC_PATTERN.sub("ghp_[REDACTED]", masked)
            masked = _GITHUB_PAT_PATTERN.sub("github_pat_[REDACTED]", masked)
            masked = _AI_KEY_PATTERN.sub("sk-[REDACTED]", masked)
            masked = _AWS_KEY_PATTERN.sub("AKIA[REDACTED]", masked)
            masked = _DSN_PASSWORD_PATTERN.sub(r"\1[REDACTED]\3", masked)
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
