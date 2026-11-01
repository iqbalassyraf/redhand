"""
Firewall Policy Engine: Orchestrates strict JSON schema validation,
AST-based semantic guardrails, and egress data loss prevention.
"""

from pathlib import Path
from typing import Any, Literal
from pydantic import BaseModel, Field
import yaml
import structlog

from .ast_guardrails import EgressTaintGuardrail, ShellASTGuardrail, SQLASTGuardrail
from .schema_validator import StrictSchemaValidator

logger = structlog.get_logger(__name__)


class FirewallVerdict(BaseModel):
    decision: Literal["ALLOW", "BLOCK"]
    reasons: list[str] = Field(default_factory=list)
    tool_name: str
    tool_type: str = "generic"
    upstream_url: str = ""
    target_audience: str = ""
    iam_provider: str = "local_sts"
    egress_dlp: bool = True


class FirewallPolicyEngine:
    """Orchestrates comprehensive multi-layer firewall evaluation for tool calls."""

    def __init__(self, policy_file_path: str | Path) -> None:
        self.policy_file_path = Path(policy_file_path)
        self.policies: dict[str, Any] = {}
        self.load_policies()

    def load_policies(self) -> None:
        if not self.policy_file_path.exists():
            logger.error("Policy file not found", path=str(self.policy_file_path))
            self.policies = {"settings": {}, "tools": {}}
            return

        with open(self.policy_file_path, "r", encoding="utf-8") as f:
            self.policies = yaml.safe_load(f) or {}

        tools_count = len(self.policies.get("tools", {}))
        logger.info("Loaded AgentWall firewall policies", tools_count=tools_count, path=str(self.policy_file_path))

    def get_tool_policy(self, tool_name: str) -> dict[str, Any] | None:
        return self.policies.get("tools", {}).get(tool_name)

    def evaluate_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_id: str,
        caller_identity: str,
        user_roles: list[str] | None = None,
    ) -> FirewallVerdict:
        tool_cfg = self.get_tool_policy(tool_name)

        # 1. Authorization & Tool Existence
        if not tool_cfg:
            msg = f"Unauthorized tool '{tool_name}': not declared in policy allowlist."
            logger.warning("Tool call blocked: unknown tool", tool=tool_name, agent_id=agent_id)
            return FirewallVerdict(
                decision="BLOCK",
                reasons=[msg],
                tool_name=tool_name,
            )

        tool_type = tool_cfg.get("type", "generic")
        upstream_url = tool_cfg.get("upstream_url", "")
        target_audience = tool_cfg.get("target_audience", "")
        iam_provider = tool_cfg.get("iam_provider", "local_sts")
        egress_dlp = tool_cfg.get("egress_dlp", True)

        violations: list[str] = []

        # 2. Per-User Permissions (On-Behalf-Of / Delegated User RBAC)
        required_user_roles = tool_cfg.get("required_user_roles")
        if required_user_roles:
            effective_roles = set(user_roles or ["default_user"])
            if not effective_roles.intersection(set(required_user_roles)):
                violations.append(
                    f"Per-User Authorization Denied: Caller '{caller_identity}' with roles {list(effective_roles)} "
                    f"lacks required roles {required_user_roles} to invoke tool '{tool_name}'."
                )

        # 3. Strict Schema Validation
        schema = tool_cfg.get("schema")
        if schema:
            is_valid, schema_violations = StrictSchemaValidator.validate(schema, arguments)
            if not is_valid:
                violations.extend(schema_violations)

        # 4. AST Semantic Guardrails (always run for deep defense reporting)
        if tool_type == "sql" and "query" in arguments:
            query = arguments.get("query", "")
            allowed_statements = tool_cfg.get("allowed_statements", ["SELECT"])
            forbidden_clauses = tool_cfg.get("forbidden_clauses", [])
            forbidden_columns = tool_cfg.get("forbidden_columns", [])
            max_rows_limit = tool_cfg.get("max_rows_limit")
            passed, sql_violations = SQLASTGuardrail.evaluate(
                query,
                allowed_statements=allowed_statements,
                forbidden_clauses=forbidden_clauses,
                forbidden_columns=forbidden_columns,
                max_rows_limit=max_rows_limit,
            )
            if not passed:
                violations.extend(sql_violations)

        elif tool_type == "shell" and "command" in arguments:
            command = arguments.get("command", "")
            allowed_binaries = tool_cfg.get("allowed_binaries", [])
            block_chaining = tool_cfg.get("block_chaining", True)
            block_subshells = tool_cfg.get("block_subshells", True)
            block_dangerous = tool_cfg.get("block_dangerous_primitives", True)
            passed, shell_violations = ShellASTGuardrail.evaluate(
                command,
                allowed_binaries=allowed_binaries,
                block_chaining=block_chaining,
                block_subshells=block_subshells,
                block_dangerous_primitives=block_dangerous,
            )
            if not passed:
                violations.extend(shell_violations)

        if violations:
            logger.warning(
                "Tool call blocked: policy or guardrail violation",
                tool=tool_name,
                violations=violations,
                agent_id=agent_id,
            )
            return FirewallVerdict(
                decision="BLOCK",
                reasons=violations,
                tool_name=tool_name,
                tool_type=tool_type,
                upstream_url=upstream_url,
                target_audience=target_audience,
                iam_provider=iam_provider,
                egress_dlp=egress_dlp,
            )

        logger.info("Tool call approved by firewall", tool=tool_name, agent_id=agent_id)
        return FirewallVerdict(
            decision="ALLOW",
            reasons=[],
            tool_name=tool_name,
            tool_type=tool_type,
            upstream_url=upstream_url,
            target_audience=target_audience,
            iam_provider=iam_provider,
            egress_dlp=egress_dlp,
        )

    def inspect_egress(self, data: Any) -> tuple[Any, list[str]]:
        """Inspects response data before returning to agent."""
        return EgressTaintGuardrail.scan_and_redact(data)

