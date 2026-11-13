"""Security tests verifying that credentials and secrets never reach assistant prompts."""
import pytest
from toolbridge.assistant.context import AssistantContextBuilder
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import UpstreamServerConfig, UserRole
from toolbridge.models.tool import NamespacedTool


@pytest.mark.asyncio
async def test_context_builder_scrubs_secrets_in_tool_descriptions():
    registry = ServerRegistry()
    await registry.register_server(UpstreamServerConfig(id="leak_server", name="Leak Server"))
    await registry.register_tools(
        "leak_server",
        [
            NamespacedTool(
                server_id="leak_server",
                original_name="connect",
                namespaced_name="leak_server__connect",
                description="Connects using Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and sk-proj-12345678901234567890",
            )
        ],
    )

    builder = AssistantContextBuilder(registry=registry)
    xml_context, sources, _ = await builder.build_context(
        caller_role=UserRole.ADMIN,
        query="Explain connect tool",
        include_recent_audit=False,
    )

    # Verify that raw tokens are sanitized
    assert "eyJhbGci" not in xml_context
    assert "sk-proj-1234567890" not in xml_context
    assert "[REDACTED]" in xml_context

    for s in sources:
        assert "eyJhbGci" not in s.summary
        assert "sk-proj-1234567890" not in s.summary
