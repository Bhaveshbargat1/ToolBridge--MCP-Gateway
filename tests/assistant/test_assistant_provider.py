"""Unit tests for Assistant Provider adapters and fallback engine."""
import pytest
from toolbridge.assistant.provider import (
    DeterministicFallbackEngine,
    MockProvider,
    get_assistant_provider,
)
from toolbridge.models.assistant import ProviderStatus


@pytest.mark.asyncio
async def test_mock_provider_keyword_heuristics():
    provider = MockProvider()
    ans, tokens = await provider.generate_response(
        system_prompt="",
        user_prompt="Why did my write_file call get blocked with a 403?",
    )
    assert "filesystem__write_file" in ans
    assert "SENSITIVE" in ans
    assert tokens is not None


@pytest.mark.asyncio
async def test_deterministic_fallback_engine_diagnoses_offline():
    fallback_text = DeterministicFallbackEngine.diagnose(
        query="Why did write_file fail with 403?",
        xml_context="<context/>",
        error_detail="Connection timeout to upstream provider",
    )
    assert "Provider Offline — Deterministic Local Diagnosis" in fallback_text
    assert "filesystem__write_file" in fallback_text
    assert "SENSITIVE" in fallback_text
    assert "Connection timeout" in fallback_text


def test_get_assistant_provider_disabled(monkeypatch):
    monkeypatch.setenv("TOOLBRIDGE_ASSISTANT_ENABLED", "false")
    provider, status, name = get_assistant_provider()
    assert status == ProviderStatus.DISABLED
    assert name == "disabled"
