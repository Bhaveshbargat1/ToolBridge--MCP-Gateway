"""Unit and integration tests for Phase C proposed actions and Phase B role simulation."""
import pytest
from toolbridge.api.auth import AuthenticatedUser
from toolbridge.assistant.service import AssistantService
from toolbridge.assistant.provider import MockProvider
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.assistant import ProposedActionType, ProviderStatus
from toolbridge.models.server import UpstreamServerConfig, UserRole
from toolbridge.models.tool import NamespacedTool


@pytest.mark.asyncio
async def test_action_proposal_creation_and_execution_lifecycle():
    registry = ServerRegistry()
    await registry.register_server(UpstreamServerConfig(id="postgres", name="PostgreSQL"))
    await registry.register_tools(
        "postgres",
        [
            NamespacedTool(
                server_id="postgres",
                original_name="describe_table",
                namespaced_name="postgres__describe_table",
                description="Describe table schema",
            )
        ],
    )

    service = AssistantService(
        registry=registry,
        provider=MockProvider(),
        provider_status=ProviderStatus.CONFIGURED,
        provider_name="mock",
    )

    # Prompt triggering action proposal
    resp = await service.process_chat(
        query="Please propose an action to reconnect postgres server.",
        caller_role=UserRole.ADMIN,
        caller_id="admin_user",
        include_recent_audit=False,
    )

    assert len(resp.proposed_actions) == 1
    action = resp.proposed_actions[0]
    assert action.action_type == ProposedActionType.SERVER_RECONNECT
    assert action.arguments["server_id"] == "postgres"
    assert action.status == "PENDING"

    # Operator tries to approve -> Denied (403)
    operator = AuthenticatedUser(caller_id="oper_01", role=UserRole.OPERATOR)
    fail_res = await service.execute_proposed_action(
        action_id=action.action_id,
        caller=operator,
        confirmed=True,
    )
    assert fail_res.success is False
    assert fail_res.status_code == 403

    # Admin approves -> Success (200)
    admin = AuthenticatedUser(caller_id="admin_01", role=UserRole.ADMIN)
    succ_res = await service.execute_proposed_action(
        action_id=action.action_id,
        caller=admin,
        confirmed=True,
    )
    assert succ_res.success is True
    assert succ_res.status_code == 200
    assert "Successfully reconnected" in str(succ_res.result) or "Simulated reconnection" in str(succ_res.result)

    # Action is now consumed and no longer pending
    assert action.action_id not in service._pending_actions
