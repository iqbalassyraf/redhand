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

from redhand_sdk.adapters.usage import (
    clean_model_name,
    extract_model,
    extract_usage,
    model_from_invocation,
    provider_from_serialized,
)
from redhand_sdk.client import RedHandClient, get_default_client
from redhand_sdk.decorators import guard, set_reasoning_context
from redhand_sdk.models import FirewallVerdict, RiskTier, StepType, TraceSpanItem


MAX_PENDING_RUNS = 1_000  # calls that started and never ended (a crashed worker): bounded so the handler cannot grow without limit


class RedHandLangChainHandler:
    """
    Duck-typed LangChain / LangGraph callback handler (compatible with
    `langchain_core.callbacks.BaseCallbackHandler` without requiring `langchain-core`
    as a hard install dependency).

    Model use: when a model call ends, the handler reports the token counts the provider gave, with the model the call reported. A call
    that reported no usage is not reported as usage, and a model nobody named is left unnamed (never a made-up default). The control
    plane prices only what is reported, so an unnamed model or provider shows as "price unknown" there. No prompt or completion text is
    read for usage.
    """

    def __init__(
        self,
        *,
        session_id: UUID | None = None,
        model_provider: str = "",
        model_name: str = "",
        client: RedHandClient | None = None,
    ) -> None:
        self.session_id = session_id or uuid4()
        self.trace_id = secrets.token_hex(16)
        self.model_provider = model_provider
        self.model_name = model_name
        self.client = client or get_default_client()
        self._step_seq = 0
        self._runs: dict[str, tuple[str, str, str]] = {}  # run id -> (provider, model, span id of the call's start span)

        set_reasoning_context(
            session_id=self.session_id,
            trace_id=self.trace_id,
        )

    @property
    def pending_runs(self) -> int:
        """Model calls started and not yet ended (exposed for tests)."""
        return len(self._runs)

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        self._step_seq += 1
        span_id = secrets.token_hex(8)
        provider = self.model_provider or provider_from_serialized(serialized)
        model = model_from_invocation(kwargs) or clean_model_name(self.model_name)
        obs_span = TraceSpanItem(
            session_id=self.session_id,
            trace_id=self.trace_id,
            span_id=span_id,
            step_sequence=self._step_seq,
            step_type=StepType.OBSERVATION,
            model_provider=provider or None,
            model_name=model or None,
            observation_payload={"prompts": prompts[:3]},
            firewall_verdict=FirewallVerdict.ALLOW,
        )
        run_key = self._run_key(kwargs)
        if run_key is not None and len(self._runs) < MAX_PENDING_RUNS:
            self._runs[run_key] = (provider, model, span_id)
        set_reasoning_context(parent_span_id=span_id)
        self.client.enqueue_span(obs_span)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Reports the call's token usage on its own span. Never raises into the caller's agent."""
        provider, model, start_span_id = self._runs.pop(self._run_key(kwargs) or "", ("", "", ""))
        try:
            prompt_tokens, completion_tokens = extract_usage(response)
            if not prompt_tokens and not completion_tokens:
                return  # the provider reported no usage: nothing to report
            model = extract_model(response) or model or clean_model_name(self.model_name)
            provider = provider or self.model_provider or ""
            self._step_seq += 1
            span = TraceSpanItem(
                session_id=self.session_id,
                trace_id=self.trace_id,
                span_id=secrets.token_hex(8),
                parent_span_id=start_span_id or None,
                step_sequence=self._step_seq,
                step_type=StepType.OBSERVATION,
                model_provider=provider or None,
                model_name=model or None,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                firewall_verdict=FirewallVerdict.ALLOW,
            )
        except Exception:  # noqa: BLE001 - telemetry must never break the agent; an unreadable result is "not reported"
            return
        self.client.enqueue_span(span)

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        self._runs.pop(self._run_key(kwargs) or "", None)

    @staticmethod
    def _run_key(kwargs: dict[str, Any]) -> str | None:
        run_id = kwargs.get("run_id")
        return str(run_id) if run_id is not None else None

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
            model_provider=self.model_provider or None,
            model_name=self.model_name or None,
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

