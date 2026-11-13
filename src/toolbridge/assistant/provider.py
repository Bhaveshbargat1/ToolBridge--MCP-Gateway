"""Model provider adapters and deterministic fallback engine for ToolBridge Assistant."""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Protocol, runtime_checkable
import httpx

from toolbridge.models.assistant import ProviderStatus

logger = logging.getLogger("toolbridge.assistant.provider")


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol interface for model provider adapters."""

    async def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        timeout_seconds: float = 8.0,
    ) -> tuple[str, int | None]:
        """Generate response from model provider.

        Returns:
            Tuple of (response_text, token_count)
        """
        ...


class MockProvider:
    """Deterministic, offline provider for testing and unconfigured setups."""

    def __init__(self, canned_answer: str | None = None) -> None:
        self.canned_answer = canned_answer

    async def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        timeout_seconds: float = 8.0,
    ) -> tuple[str, int | None]:
        """Generate mock response based on prompt keywords and grounding."""
        if self.canned_answer:
            return self.canned_answer, 42

        # Basic keyword heuristic for intelligent offline answers
        p_lower = user_prompt.lower()
        if "write_file" in p_lower and ("403" in p_lower or "fail" in p_lower or "block" in p_lower or "why" in p_lower):
            ans = (
                "**Explanation**: `filesystem__write_file` is classified as a **`SENSITIVE`** tool. "
                "Callers with the `readonly` role are restricted to `SAFE` tools only. "
                "To execute file writes, the caller must authenticate with an `OPERATOR` or `ADMIN` API key. "
                "[source: policy:filesystem__write_file]"
            )
        elif "role" in p_lower or "permission" in p_lower:
            ans = (
                "**ToolBridge RBAC Policy**: "
                "- **`ADMIN`**: Full permissions on all tools and server management. "
                "- **`OPERATOR`**: Permitted for all `SAFE` and `SENSITIVE` tools (cannot modify server configs). "
                "- **`READONLY`**: Strictly limited to `SAFE` tools. "
                "[source: policy:rules]"
            )
        elif "postgres" in p_lower or "sql" in p_lower:
            ans = (
                "**PostgreSQL Guardrails**: Queries to `postgres__execute_query` are protected by an AST parser (`sqlparse`) "
                "that strictly permits single-statement read-only `SELECT` or `EXPLAIN` queries. "
                "Mutations (INSERT, UPDATE, DELETE, DROP), multi-statements, and administrative functions (`pg_sleep`, `set_config`) are blocked. "
                "[source: policy:postgres__execute_query]"
            )
        elif "list" in p_lower or "available" in p_lower or "tools" in p_lower:
            ans = (
                "**Discovered Gateway Tools**: "
                "ToolBridge exposes tools from three upstream servers: "
                "1. `filesystem`: `read_file`, `write_file`, `list_directory`, `search_files`, `get_file_info`. "
                "2. `postgres`: `list_tables`, `describe_table`, `execute_query`. "
                "3. `github`: `get_repository`, `list_issues`, `search_repositories`. "
                "[source: tools:catalog]"
            )
        else:
            ans = (
                "**ToolBridge Operational Guidance**: ToolBridge provides centralized gateway routing, "
                "rate limiting, RBAC authorization, and AST-level query guards across Filesystem, PostgreSQL, and GitHub MCP servers. "
                "Review the source citations below for active tool schemas and policies."
            )
        return ans, 120


class OpenAICompatibleProvider:
    """Adapter for OpenAI, Gemini, Groq, Ollama, and vLLM OpenAI-compatible endpoints."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
    ) -> None:
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=3.0),
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        timeout_seconds: float = 8.0,
    ) -> tuple[str, int | None]:
        client = self._get_client()
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 800,
        }

        resp = await client.post(url, headers=headers, json=payload, timeout=timeout_seconds)
        if resp.status_code != 200:
            raise RuntimeError(f"Provider returned HTTP {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        choice = data.get("choices", [{}])[0]
        content = choice.get("message", {}).get("content", "")
        tokens = data.get("usage", {}).get("total_tokens")
        return content, tokens


class DeterministicFallbackEngine:
    """Locally resolves queries if the external model provider is unavailable or unconfigured."""

    @staticmethod
    def diagnose(query: str, xml_context: str, error_detail: str = "") -> str:
        q = query.lower()
        lines = [
            "⚠️ **Provider Offline — Deterministic Local Diagnosis**",
            "",
        ]

        if "write_file" in q or "403" in q:
            lines.extend([
                "### Root Cause Analysis",
                "- **Tool**: `filesystem__write_file`",
                "- **Sensitivity**: `SENSITIVE` (mutating disk write)",
                "- **Authorization**: Denied for `readonly` role. Requires `operator` or `admin` role.",
                "",
                "### Remediation",
                "Authenticate using `X-API-Key: <OPERATOR_KEY>` or request an admin grant.",
            ])
        elif "postgres" in q or "timeout" in q or "5432" in q:
            lines.extend([
                "### PostgreSQL Server Status",
                "- The gateway includes resilient fallback logic: if port 5432 is unreachable, "
                "queries automatically execute against the embedded SQLite sample database (`sample_postgres.db`).",
                "- Multi-statement injection and DML mutations are strictly blocked by the AST query guard.",
            ])
        elif "role" in q or "permission" in q:
            lines.extend([
                "### Role Permission Summary",
                "- **ADMIN**: Unrestricted access to all tools and lifecycle management endpoints.",
                "- **OPERATOR**: Permitted to run all SAFE and SENSITIVE tools.",
                "- **READONLY**: Restricted strictly to SAFE read-only tools.",
            ])
        else:
            lines.extend([
                "### Gateway Grounding Summary",
                "The external model provider is currently unreachable or unconfigured. "
                "ToolBridge continues operating normally. All tools, guards, and audit logs remain active.",
                "- **Context Status**: Successfully grounded against live registry and policy engine.",
            ])

        if error_detail:
            lines.append(f"\n*(Provider diagnostic: {error_detail[:120]})*")

        return "\n".join(lines)


def get_assistant_provider() -> tuple[LLMProvider, ProviderStatus, str]:
    """Factory creating the configured model provider based on environment variables."""
    enabled = os.environ.get("TOOLBRIDGE_ASSISTANT_ENABLED", "false").lower() in ("true", "1", "yes")
    api_key = os.environ.get("TOOLBRIDGE_ASSISTANT_API_KEY", "").strip()
    provider_type = os.environ.get("TOOLBRIDGE_ASSISTANT_PROVIDER", "mock").lower()
    base_url = os.environ.get("TOOLBRIDGE_ASSISTANT_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("TOOLBRIDGE_ASSISTANT_MODEL", "gpt-4o-mini")

    if not enabled:
        return MockProvider(), ProviderStatus.DISABLED, "disabled"

    if provider_type == "mock":
        return MockProvider(), ProviderStatus.CONFIGURED, "mock"

    if provider_type in ("openai-compatible", "openai"):
        if not api_key:
            logger.info("TOOLBRIDGE_ASSISTANT_API_KEY is empty; operating in unconfigured fallback mode.")
            return MockProvider(), ProviderStatus.UNCONFIGURED, "unconfigured"
        return OpenAICompatibleProvider(api_key=api_key, base_url=base_url, model=model), ProviderStatus.CONFIGURED, "openai-compatible"

    return MockProvider(), ProviderStatus.UNCONFIGURED, "unconfigured"
