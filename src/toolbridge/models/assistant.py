"""Pydantic schemas and domain models for ToolBridge Operational Assistant."""
from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from toolbridge.models.server import UserRole
from toolbridge.security.policy import SensitivityTier


class ProviderStatus(str, Enum):
    """Operational status of the external model provider."""
    CONFIGURED = "CONFIGURED"
    UNCONFIGURED = "UNCONFIGURED"
    DEGRADED = "DEGRADED"
    DISABLED = "DISABLED"


class SourceReferenceType(str, Enum):
    """Categorization of grounding sources backing assistant answers."""
    TOOL_SCHEMA = "TOOL_SCHEMA"
    POLICY_RULE = "POLICY_RULE"
    AUDIT_LOG = "AUDIT_LOG"
    CONFIGURATION = "CONFIGURATION"
    DOCUMENTATION = "DOCUMENTATION"


class SourceReference(BaseModel):
    """Verifiable source citation grounding an assistant claim."""
    source_type: SourceReferenceType
    identifier: str = Field(..., description="Unique source identifier (e.g. 'tools:filesystem__write_file')")
    summary: str = Field(..., description="Brief factual snippet extracted from the source")


class ProposedActionType(str, Enum):
    """Types of actions that can be proposed for human approval."""
    TOOL_INVOCATION = "TOOL_INVOCATION"
    SERVER_RECONNECT = "SERVER_RECONNECT"
    CONFIG_RECOMMENDATION = "CONFIG_RECOMMENDATION"


class ProposedAction(BaseModel):
    """A proposed gateway action requiring explicit human review and authorization."""
    action_id: str = Field(..., description="Unique identifier for the action proposal")
    action_type: ProposedActionType = Field(..., description="Type of proposed action")
    title: str = Field(..., description="Human-readable title of the proposed action")
    description: str = Field(..., description="Impact and justification for the action")
    tool_name: str | None = Field(default=None, description="Target tool name if applicable")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Target tool parameters")
    requires_role: UserRole = Field(default=UserRole.ADMIN, description="Minimum role required to approve")
    sensitivity_tier: SensitivityTier = Field(default=SensitivityTier.SENSITIVE, description="Sensitivity classification")
    status: str = Field(default="PENDING", description="Status: PENDING, EXECUTED, REJECTED")


class AssistantChatRequest(BaseModel):
    """Inbound operator query payload."""
    query: str = Field(..., min_length=2, max_length=2000, description="Operator question")
    include_recent_audit: bool = Field(default=True, description="Whether to include recent failure summaries")
    simulated_role: UserRole | None = Field(
        default=None,
        description="Phase B: Optional simulated role to evaluate permissions against (e.g. 'readonly')",
    )
    session_id: str | None = Field(default=None, max_length=64, description="Ephemeral client session key")


class AssistantChatResponse(BaseModel):
    """Structured, evidence-backed assistant response."""
    answer: str = Field(..., description="Markdown formatted explanation or recommendation")
    sources: list[SourceReference] = Field(default_factory=list, description="Grounding references")
    proposed_actions: list[ProposedAction] = Field(default_factory=list, description="Phase C: Proposed actions")
    simulated_evaluation: dict[str, Any] | None = Field(
        default=None,
        description="Phase B: Results of simulated role permission check",
    )
    provider_status: ProviderStatus
    provider_name: str = Field(default="mock", description="Configured provider (e.g. 'openai-compatible', 'fallback')")
    latency_ms: float = Field(..., description="Round-trip orchestration latency")
    tokens_used: int | None = Field(default=None, description="Tokens consumed if reported by provider")


class AssistantStatusResponse(BaseModel):
    """Provider health and availability status."""
    enabled: bool
    status: ProviderStatus
    provider_name: str
    model_name: str
    rate_limit_per_minute: int
    timeout_seconds: float


class ActionExecutionRequest(BaseModel):
    """Payload for approving and executing a previously proposed action."""
    action_id: str = Field(..., description="ID of the proposed action to execute")
    confirmed_by_admin: bool = Field(..., description="Explicit human acknowledgment checkbox")
    reason: str | None = Field(default=None, description="Operator justification for approval")


class ActionExecutionResponse(BaseModel):
    """Result of executing an approved action through gateway guards."""
    action_id: str
    success: bool
    status_code: int
    result: Any
    duration_ms: float
