"""Unit tests for AssistantContextBuilder (grounding and XML formatting)."""
import pytest
from toolbridge.assistant.context import AssistantContextBuilder
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import UpstreamServerConfig, UserRole
from toolbridge.models.tool import NamespacedTool


@pytest.mark.asyncio
async def test_context_builder_assembles_tools_and_servers():
    registry = ServerRegistry()
    await registry.register_server(
        UpstreamServerConfig(id="test_server", name="Test Server")
    )
    await registry.register_tools(
        "test_server",
        [
            NamespacedTool(
                server_id="test_server",
                original_name="echo",
                namespaced_name="test_server__echo",
                description="Echoes input back to caller",
                input_schema={"type": "object", "properties": {"msg": {"type": "string"}}},
            )
        ],
    )

    builder = AssistantContextBuilder(registry=registry)
    xml_context, sources, sim_eval = await builder.build_context(
        caller_role=UserRole.OPERATOR,
        query="What tools exist?",
        include_recent_audit=False,
    )

    assert "<context>" in xml_context
    assert "</context>" in xml_context
    assert "test_server__echo" in xml_context
    assert "<caller_identity role='operator'/>" in xml_context
    assert sim_eval is None

    # Check source citations
    identifiers = [s.identifier for s in sources]
    assert "server:test_server" in identifiers
    assert "tools:test_server__echo" in identifiers
    assert "policy:test_server__echo" in identifiers


@pytest.mark.asyncio
async def test_phase_b_simulated_role_evaluation():
    registry = ServerRegistry()
    await registry.register_server(UpstreamServerConfig(id="fs", name="Filesystem"))
    await registry.register_tools(
        "fs",
        [
            NamespacedTool(
                server_id="fs",
                original_name="read_file",
                namespaced_name="filesystem__read_file",
                description="Read safe file",
            ),
            NamespacedTool(
                server_id="fs",
                original_name="write_file",
                namespaced_name="filesystem__write_file",
                description="Write sensitive file",
            ),
        ],
    )

    builder = AssistantContextBuilder(registry=registry)
    xml_context, sources, sim_eval = await builder.build_context(
        caller_role=UserRole.ADMIN,
        query="Simulate readonly",
        simulated_role=UserRole.READONLY,
        include_recent_audit=False,
    )

    assert sim_eval is not None
    assert sim_eval["simulated_role"] == "readonly"
    assert sim_eval["permitted_count"] == 1  # read_file is SAFE
    assert sim_eval["restricted_count"] == 1  # write_file is SENSITIVE

    permitted_names = [t["tool_name"] for t in sim_eval["permitted_tools"]]
    restricted_names = [t["tool_name"] for t in sim_eval["restricted_tools"]]
    assert "filesystem__read_file" in permitted_names
    assert "filesystem__write_file" in restricted_names
