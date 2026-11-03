"""
RedHand Core - Declarative Policy-as-Code (PaC) Engine
File: services/redhand-core/src/redhand_core/services/policy_engine.py

Evaluates declarative security policies against agent identities, tools,
target cloud resources, and risk tiers prior to tool dispatch and IAM minting.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import fnmatch
import logging

logger = logging.getLogger("redhand.core.policy_engine")


class PolicyEffect(str, Enum):
    ALLOW = "allow"
    FORBID = "forbid"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_FOUR_EYES = "require_four_eyes"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    description: str
    effect: PolicyEffect
    environments: tuple[str, ...] | None = None
    tool_patterns: tuple[str, ...] | None = None
    resource_patterns: tuple[str, ...] | None = None
    risk_tiers: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    requires_hitl: bool
    required_approvals: int
    matched_rule_id: str | None
    reason: str


# Default enterprise baseline policies
DEFAULT_POLICIES: tuple[PolicyRule, ...] = (
    PolicyRule(
        rule_id="RH-PAC-001",
        description="Forbid non-production agents from modifying production cloud resources.",
        effect=PolicyEffect.FORBID,
        environments=("development", "staging"),
        resource_patterns=("*prod*", "*production*", "*live*"),
        risk_tiers=("state_mutation", "destructive", "critical"),
    ),
    PolicyRule(
        rule_id="RH-PAC-002",
        description="Enforce Four-Eyes Principle (2 approvals) for destructive production changes.",
        effect=PolicyEffect.REQUIRE_FOUR_EYES,
        environments=("production",),
        risk_tiers=("destructive", "critical"),
    ),
    PolicyRule(
        rule_id="RH-PAC-003",
        description="Standard single-signature approval for state-mutating actions.",
        effect=PolicyEffect.REQUIRE_APPROVAL,
        risk_tiers=("state_mutation",),
    ),
)


class PolicyEngine:
    """
    Evaluates declarative policies against agent execution context.
    """

    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self._rules = tuple(rules) if rules is not None else DEFAULT_POLICIES

    def evaluate(
        self,
        *,
        agent_environment: str,
        tool_name: str,
        risk_tier: str,
        target_resource: str | None = None,
    ) -> PolicyDecision:
        for rule in self._rules:
            if not self._matches_rule(
                rule=rule,
                agent_environment=agent_environment,
                tool_name=tool_name,
                risk_tier=risk_tier,
                target_resource=target_resource,
            ):
                continue

            if rule.effect == PolicyEffect.FORBID:
                return PolicyDecision(
                    allowed=False,
                    requires_hitl=False,
                    required_approvals=0,
                    matched_rule_id=rule.rule_id,
                    reason=f"Policy '{rule.rule_id}' explicitly forbids action: {rule.description}",
                )

            if rule.effect == PolicyEffect.REQUIRE_FOUR_EYES:
                return PolicyDecision(
                    allowed=True,
                    requires_hitl=True,
                    required_approvals=2,
                    matched_rule_id=rule.rule_id,
                    reason=f"Four-Eyes Principle enforced by '{rule.rule_id}': 2 human operator signatures required.",
                )

            if rule.effect == PolicyEffect.REQUIRE_APPROVAL:
                return PolicyDecision(
                    allowed=True,
                    requires_hitl=True,
                    required_approvals=1,
                    matched_rule_id=rule.rule_id,
                    reason=f"Approval required by '{rule.rule_id}': {rule.description}",
                )

        # Default fallback: READ_ONLY is allowed directly; others require 1 approval
        is_read_only = risk_tier == "read_only"
        return PolicyDecision(
            allowed=True,
            requires_hitl=not is_read_only,
            required_approvals=0 if is_read_only else 1,
            matched_rule_id="default-baseline",
            reason="Standard runtime policy applied.",
        )

    @staticmethod
    def _matches_rule(
        *,
        rule: PolicyRule,
        agent_environment: str,
        tool_name: str,
        risk_tier: str,
        target_resource: str | None,
    ) -> bool:
        if rule.environments and agent_environment not in rule.environments:
            return False

        if rule.risk_tiers and risk_tier not in rule.risk_tiers:
            return False

        if rule.tool_patterns and not any(
            fnmatch.fnmatch(tool_name, pat) for pat in rule.tool_patterns
        ):
            return False

        if rule.resource_patterns:
            if not target_resource:
                return False
            if not any(
                fnmatch.fnmatch(target_resource.lower(), pat.lower())
                for pat in rule.resource_patterns
            ):
                return False

        return True


_default_policy_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    global _default_policy_engine
    if _default_policy_engine is None:
        _default_policy_engine = PolicyEngine()
    return _default_policy_engine

