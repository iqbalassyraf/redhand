"""
RedHand SDK - CrewAI Runtime Adapter
File: packages/redhand-sdk/src/redhand_sdk/adapters/crewai.py

Provides `create_crewai_step_callback()` to plug directly into `Crew(step_callback=...)`
or `Agent(step_callback=...)`, recording CrewAI `Thought` traces and linking them
to `@guard`-protected tools.
"""

from __future__ import annotations

import secrets
from typing import Any, Callable
from uuid import UUID, uuid4

from redhand_sdk.client import RedHandClient, get_default_client
from redhand_sdk.decorators import set_reasoning_context
from redhand_sdk.models import FirewallVerdict, StepType, TraceSpanItem


def create_crewai_step_callback(
    *,
    session_id: UUID | None = None,
    client: RedHandClient | None = None,
) -> Callable[[Any], None]:
    """
    Returns a callback function suitable for CrewAI's `step_callback` parameter.
    Extracts the agent's thought and tool output at every reasoning step.
    """
    active_session_id = session_id or uuid4()
    trace_id = secrets.token_hex(16)
    active_client = client or get_default_client()
    step_counter = 0

    def _on_crew_step(step_output: Any) -> None:
        nonlocal step_counter
        step_counter += 1
        span_id = secrets.token_hex(8)

        thought = getattr(step_output, "thought", None) or getattr(
            step_output, "text", str(step_output)
        )
        tool_name = getattr(step_output, "tool", None)

        set_reasoning_context(
            session_id=active_session_id,
            trace_id=trace_id,
            parent_span_id=span_id,
            thought=str(thought),
        )

        span = TraceSpanItem(
            session_id=active_session_id,
            trace_id=trace_id,
            span_id=span_id,
            step_sequence=step_counter,
            step_type=StepType.THOUGHT,
            thought_content=str(thought)[:32768],
            tool_name=str(tool_name) if tool_name else None,
            firewall_verdict=FirewallVerdict.ALLOW,
        )
        active_client.enqueue_span(span)

    return _on_crew_step

