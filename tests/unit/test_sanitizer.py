"""Unit tests for SecretSanitizer credential scrubbing."""
import json
import pytest
from toolbridge.security.sanitizer import SecretSanitizer


@pytest.mark.unit
def test_sensitive_dict_keys_redacted():
    """Verify dictionary keys matching sensitive patterns are masked."""
    payload = {
        "username": "developer",
        "password": "SuperSecretPassword123!",
        "api_key": "live_key_9876543210",
        "nested": {
            "auth_token": "token_abc_xyz",
            "safe_property": "normal_value",
        },
        "tags": ["public", "safe"],
    }

    sanitized = SecretSanitizer.sanitize(payload)
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["auth_token"] == "[REDACTED]"
    assert sanitized["nested"]["safe_property"] == "normal_value"
    assert sanitized["username"] == "developer"


@pytest.mark.unit
def test_bearer_and_github_tokens_scrubbed_in_strings():
    """Verify bearer tokens and GitHub PATs in string text are masked."""
    text = "Connecting with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    sanitized = SecretSanitizer.sanitize(text)

    assert "Bearer [REDACTED]" in sanitized
    assert "eyJhbGci" not in sanitized
    assert "ghp_[REDACTED]" in sanitized
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in sanitized


@pytest.mark.unit
def test_to_sanitized_json():
    """Verify serialization to sanitized JSON string."""
    data = {"secret_key": "12345", "query": "SELECT * FROM users"}
    json_str = SecretSanitizer.to_sanitized_json(data)
    parsed = json.loads(json_str)

    assert parsed["secret_key"] == "[REDACTED]"
    assert parsed["query"] == "SELECT * FROM users"
