"""Context builder for ToolBridge Operational Assistant.

Extracts deterministic tool catalog definitions, RBAC policies, server health statuses,
and sanitized audit logs into XML-delimited grounding text with verifiable source citations.
"""
from __future__ import annotations

import logging
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession

from toolbridge.client.registry import ServerRegistry
from toolbridge.models.assistant import SourceReference, SourceReferenceType
from toolbridge.models.server import UserRole
from toolbridge.security.audit_service import AuditService
from toolbridge.security.policy import PolicyEngine
from toolbridge.security.sanitizer import SecretSanitizer

logger = logging.getLogger("toolbridge.assistant.context")


class AssistantContextBuilder:
    """Builds grounded, role-filtered context for the operational assistant."""

    def __init__(self, registry: ServerRegistry) -> None:
        self.registry = registry

    async def build_context(
        self,
        caller_role: UserRole,
        query: str,
        include_recent_audit: bool = True,
        simulated_role: UserRole | None = None,
        db_session: AsyncSession | None = None,
    ) -> tuple[str, list[SourceReference], dict[str, Any] | None]:
        """Compile XML grounding text and source citations.

        Returns:
            Tuple of:
            - xml_context: Sanitized XML-formatted grounding block
            - sources: List of SourceReference objects for operator verification
            - simulated_evaluation: Optional dict of Phase B simulated role permissions
        """
        sources: list[SourceReference] = []

        # 1. Server Inventory
        servers = await self.registry.get_all_servers()
        server_lines = []
        for s in servers:
            s_id = s.config.id
            s_name = s.config.name
            s_trans = s.config.transport.value
            s_stat = s.status.value
            s_info = f"server_id='{s_id}' name='{s_name}' status='{s_stat}' transport='{s_trans}'"
            server_lines.append(f"  <server {s_info}/>")
            sources.append(
                SourceReference(
                    source_type=SourceReferenceType.CONFIGURATION,
                    identifier=f"server:{s_id}",
                    summary=f"Server '{s_name}' [{s_stat}] via {s_trans}",
                )
            )

        # 2. Tool Catalog & Policy Evaluation
        tools = await self.registry.get_all_tools()
        tool_lines = []
        for t in tools:
            tier = PolicyEngine.get_tool_sensitivity(t.namespaced_name)
            is_auth, reason = PolicyEngine.is_authorized(caller_role, t.namespaced_name)

            desc = SecretSanitizer.sanitize(t.description or "")
            req_args = []
            if t.input_schema and isinstance(t.input_schema, dict):
                req_args = t.input_schema.get("required", [])

            t_info = (
                f"name='{t.namespaced_name}' server='{t.server_id}' tier='{tier.value}' "
                f"caller_allowed='{is_auth}' required_params='{req_args}'"
            )
            tool_lines.append(f"  <tool {t_info}>\n    <description>{desc}</description>\n  </tool>")

            # Add source references
            sources.append(
                SourceReference(
                    source_type=SourceReferenceType.TOOL_SCHEMA,
                    identifier=f"tools:{t.namespaced_name}",
                    summary=f"{t.namespaced_name} ({tier.value}): {desc[:90]}",
                )
            )
            sources.append(
                SourceReference(
                    source_type=SourceReferenceType.POLICY_RULE,
                    identifier=f"policy:{t.namespaced_name}",
                    summary=f"Role '{caller_role.value}' -> {'ALLOWED' if is_auth else 'DENIED'}. Reason: {reason}",
                )
            )

        # 3. Phase B: Simulated Role Evaluation (if requested)
        simulated_eval: dict[str, Any] | None = None
        if simulated_role is not None:
            permitted = []
            restricted = []
            for t in tools:
                allowed, r_reason = PolicyEngine.is_authorized(simulated_role, t.namespaced_name)
                tier = PolicyEngine.get_tool_sensitivity(t.namespaced_name)
                entry = {
                    "tool_name": t.namespaced_name,
                    "sensitivity_tier": tier.value,
                    "reason": r_reason,
                }
                if allowed:
                    permitted.append(entry)
                else:
                    restricted.append(entry)

            simulated_eval = {
                "simulated_role": simulated_role.value,
                "permitted_count": len(permitted),
                "restricted_count": len(restricted),
                "permitted_tools": permitted,
                "restricted_tools": restricted,
            }

        # 4. Role-Gated Recent Audit Failures
        audit_lines = []
        if include_recent_audit and db_session is not None and caller_role in (UserRole.ADMIN, UserRole.OPERATOR):
            try:
                # Query recent non-success records
                all_logs = await AuditService.query_logs(session=db_session, limit=20)
                failure_logs = [l for l in all_logs if l.status in ("ERROR", "UNAUTHORIZED", "RATE_LIMITED", "BLOCKED")][:5]
                for f_log in failure_logs:
                    clean_summary = SecretSanitizer.sanitize(f_log.response_summary or "")
                    clean_args = SecretSanitizer.sanitize(f_log.arguments_json or "{}")
                    if len(str(clean_args)) > 150:
                        clean_args = str(clean_args)[:150] + "..."

                    ev_info = (
                        f"id='{f_log.id}' tool='{f_log.tool_name}' caller='{f_log.caller_id}' "
                        f"status='{f_log.status}' duration_ms='{f_log.duration_ms}'"
                    )
                    audit_lines.append(
                        f"  <failure_event {ev_info}>\n"
                        f"    <reason>{clean_summary}</reason>\n"
                        f"    <args>{clean_args}</args>\n"
                        f"  </failure_event>"
                    )
                    sources.append(
                        SourceReference(
                            source_type=SourceReferenceType.AUDIT_LOG,
                            identifier=f"audit:#{f_log.id}",
                            summary=f"[{f_log.status}] '{f_log.tool_name}' by '{f_log.caller_id}': {clean_summary[:80]}",
                        )
                    )
            except Exception as e:
                logger.warning(f"Failed to load audit context: {e}")

        # Assemble XML block
        xml_parts = [
            "<context>",
            f"  <caller_identity role='{caller_role.value}'/>",
            "  <server_inventory>",
            *server_lines,
            "  </server_inventory>",
            "  <tool_catalog>",
            *tool_lines,
            "  </tool_catalog>",
        ]

        if audit_lines:
            xml_parts.extend(["  <recent_failures>", *audit_lines, "  </recent_failures>"])

        if simulated_eval:
            sim_role_val = simulated_eval["simulated_role"]
            xml_parts.append(
                f"  <simulated_role_profile role='{sim_role_val}' "
                f"permitted_count='{simulated_eval['permitted_count']}' "
                f"restricted_count='{simulated_eval['restricted_count']}'/>"
            )

        xml_parts.append("</context>")
        xml_context = "\n".join(xml_parts)

        return xml_context, sources, simulated_eval
