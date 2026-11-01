"""
RedHand SDK - LangChain & LangGraph Runtime Adapter
File: packages/redhand-sdk/src/redhand_sdk/adapters/langchain.py

Provides:
1. `RedHandCallbackHandler`: Captures LLM `Observation -> Thought` steps and sets
   the coroutine reasoning context automatically before tool invocation.
2. `guard_langchain_tools()`: Wraps a list of LangChain `BaseTool` / `StructuredTool`
   objects with RedHand's `<50ms` Semantic Firewall, Ephemeral IAM, and HITL circuit breaker.
"""

from __future__ import annotations

import secrets
from typing import Any
from uuid import UUID, uuid4

from redhand_sdk.client import RedHandClient, get_default_client
from redhand_sdk.decorators import guard, set_reasoning_context
from redhand_sdk.models import FirewallVerdict, RiskTier, StepType, TraceSpanItem


class RedHandLangChainHandler:
    """
    Duck-typed LangChain / LangGraph callback handler (compatible with
    `langchain_core.callbacks.BaseCallbackHandler` without requiring `langchain-core`
    as a hard install dependency).
    """

    def __init__(
        self,
        *,
        session_id: UUID | None = None,
        model_provider: str = "google-vertex",
        model_name: str = "gemini-2.5-pro",
        client: RedHandClient | None = None,
    ) -> None:
        self.session_id = session_id or uuid4()
        self.trace_id = secrets.token_hex(16)
        self.model_provider = model_provider
        self.model_name = model_name
        self.client = client or get_default_client()
        self._step_seq = 0

        set_reasoning_context(
            session_id=self.session_id,
            trace_id=self.trace_id,
        )

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        self._step_seq += 1
        span_id = secrets.token_hex(8)
        obs_span = TraceSpanItem(
            session_id=self.session_id,
            trace_id=self.trace_id,
            span_id=span_id,
            step_sequence=self._step_seq,
            step_type=StepType.OBSERVATION,
            model_provider=self.model_provider,
            model_name=serialized.get("name", self.model_name),
            observation_payload={"prompts": prompts[:3]},
            firewall_verdict=FirewallVerdict.ALLOW,
        )
        set_reasoning_context(parent_span_id=span_id)
        self.client.enqueue_span(obs_span)

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:
        """Captures the agent's `log` (chain-of-thought) prior to tool execution."""
        thought_text = getattr(action, "log", None) or str(action)
        self._step_seq += 1
        span_id = secrets.token_hex(8)

        set_reasoning_context(
            thought=thought_text,
            trace_id=self.trace_id,
            parent_span_id=span_id,
        )

        thought_span = TraceSpanItem(
            session_id=self.session_id,
            trace_id=self.trace_id,
            span_id=span_id,
            step_sequence=self._step_seq,
            step_type=StepType.THOUGHT,
            model_provider=self.model_provider,
            model_name=self.model_name,
            thought_content=thought_text,
            tool_name=getattr(action, "tool", None),
            firewall_verdict=FirewallVerdict.ALLOW,
        )
        self.client.enqueue_span(thought_span)


def guard_langchain_tools(
    tools: list[Any],
    *,
    risk_tiers: dict[str, RiskTier] | None = None,
    default_risk_tier: RiskTier = RiskTier.READ_ONLY,
    raise_on_block: bool = False,
    raise_on_hitl: bool = False,
) -> list[Any]:
    """
    Wraps a sequence of LangChain tools (or callables) in-place with `@guard`.
    """
    tier_map = risk_tiers or {}
    guarded_list: list[Any] = []

    for tool_obj in tools:
        t_name = getattr(tool_obj, "name", getattr(tool_obj, "__name__", "unknown_tool"))
        tier = tier_map.get(t_name, default_risk_tier)

        if hasattr(tool_obj, "func") and callable(tool_obj.func):
            tool_obj.func = guard(
                tool_name=t_name,
                risk_tier=tier,
                raise_on_block=raise_on_block,
                raise_on_hitl=raise_on_hitl,
            )(tool_obj.func)
        if hasattr(tool_obj, "coroutine") and callable(tool_obj.coroutine):
            tool_obj.coroutine = guard(
                tool_name=t_name,
                risk_tier=tier,
                raise_on_block=raise_on_block,
                raise_on_hitl=raise_on_hitl,
            )(tool_obj.coroutine)
        elif callable(tool_obj) and not hasattr(tool_obj, "func"):
            tool_obj = guard(
                tool_name=t_name,
                risk_tier=tier,
                raise_on_block=raise_on_block,
                raise_on_hitl=raise_on_hitl,
            )(tool_obj)

        guarded_list.append(tool_obj)

    return guarded_list

