"""Unit tests for ToolBridge Assistant Pydantic schemas and domain models."""
import pytest
from toolbridge.models.assistant import (
    ActionExecutionRequest,
    ActionExecutionResponse,
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantStatusResponse,
    ProposedAction,
    ProposedActionType,
    ProviderStatus,
    SourceReference,
    SourceReferenceType,
)
from toolbridge.models.server import UserRole
from toolbridge.security.policy import SensitivityTier


def test_source_reference_model():
    ref = SourceReference(
        source_type=SourceReferenceType.TOOL_SCHEMA,
        identifier="tools:filesystem__read_file",
        summary="Reads files within sandbox.",
    )
    assert ref.source_type == SourceReferenceType.TOOL_SCHEMA
    assert ref.identifier == "tools:filesystem__read_file"
    assert "Reads files" in ref.summary


def test_proposed_action_model():
    action = ProposedAction(
        action_id="act_test_01",
        action_type=ProposedActionType.TOOL_INVOCATION,
        title="Execute read_file",
        description="Read sandbox note",
        tool_name="filesystem__read_file",
        arguments={"path": "note.txt"},
        requires_role=UserRole.OPERATOR,
        sensitivity_tier=SensitivityTier.SAFE,
    )
    assert action.action_id == "act_test_01"
    assert action.status == "PENDING"
    assert action.requires_role == UserRole.OPERATOR


def test_assistant_chat_request_validation():
    req = AssistantChatRequest(
        query="What tools are available?",
        include_recent_audit=False,
        simulated_role=UserRole.READONLY,
    )
    assert req.query == "What tools are available?"
    assert req.include_recent_audit is False
    assert req.simulated_role == UserRole.READONLY

    with pytest.raises(Exception):
        AssistantChatRequest(query="a")  # Too short (min length 2)


def test_assistant_chat_response_serialization():
    resp = AssistantChatResponse(
        answer="Here are the tools.",
        sources=[
            SourceReference(
                source_type=SourceReferenceType.CONFIGURATION,
                identifier="server:filesystem",
                summary="Filesystem server",
            )
        ],
        proposed_actions=[],
        provider_status=ProviderStatus.CONFIGURED,
        provider_name="mock",
        latency_ms=12.5,
    )
    data = resp.model_dump()
    assert data["answer"] == "Here are the tools."
    assert len(data["sources"]) == 1
    assert data["latency_ms"] == 12.5
    assert data["provider_status"] == "CONFIGURED"
