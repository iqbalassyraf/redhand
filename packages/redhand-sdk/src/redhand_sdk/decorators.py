"""
RedHand SDK - Tool Execution Interceptor (@guard)
File: packages/redhand-sdk/src/redhand_sdk/decorators.py

Intercepts agent tool invocations to enforce:
1. <50ms In-Memory Semantic Firewall evaluation (Tier 0 + Tier 1 ONNX).
2. Execution Blast Radius Containment (HITL Circuit Breaker checkpointing).
3. Multi-Cloud Ephemeral IAM (Single-use GCP STS / AWS STS downscoped token injection & zeroization).
4. Resilience & Enterprise Fail-Safe Modes (FAIL_OPEN vs FAIL_CLOSED).
5. OpenTelemetry-aligned reasoning trace shipping to `redhand-core`.
"""

from __future__ import annotations

import asyncio
import contextvars
import ctypes
import functools
import hashlib
import inspect
import json
import logging
import os
import secrets
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, ParamSpec, TypeVar
from uuid import UUID, uuid4

from pydantic import HttpUrl

from redhand_sdk.client import RedHandClient, get_default_client
from redhand_sdk.firewall.engine import FirewallEngine, FirewallEvaluationResult, get_default_firewall
from redhand_sdk.models import (
    AWSEphemeralTokenMintResponse,
    EphemeralTokenMintResponse,
    FailureMode,
    FirewallVerdict,
    HITLCheckpointPayload,
    HITLCheckpointReceipt,
    RiskTier,
    SecurityEventType,
    SecurityFindingPayload,
    SeverityLevel,
    StepType,
    TraceSpanItem,
)

logger = logging.getLogger("redhand.sdk.decorator")

P = ParamSpec("P")
R = TypeVar("R")

# Coroutine-safe context variables for trace correlation and ephemeral credentials
_current_session_id: contextvars.ContextVar[UUID] = contextvars.ContextVar(
    "redhand_session_id", default=uuid4()
)
_current_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "redhand_trace_id", default=""
)
_current_parent_span_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "redhand_parent_span_id", default=None
)
_current_agent_thought: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "redhand_agent_thought", default=None
)
_ephemeral_gcp_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "redhand_ephemeral_gcp_token", default=None
)
_ephemeral_aws_creds: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar(
    "redhand_ephemeral_aws_creds", default=None
)


# =============================================================================
# 1. EXCEPTIONS & STRUCTURED HALT RESULTS
# =============================================================================


class RedHandSecurityError(PermissionError):
    """Raised when the Semantic Firewall blocks a tool call and `raise_on_block=True`."""

    def __init__(self, finding: SecurityFindingPayload, span_id: str) -> None:
        self.finding = finding
        self.span_id = span_id
        super().__init__(
            f"[REDHAND_FIREWALL_BLOCKED] ({finding.event_type.value}): {finding.mitigation_action}"
        )


class RedHandHITLPausedError(RuntimeError):
    """Raised when a tool call trips the HITL circuit breaker and `raise_on_hitl=True`."""

    def __init__(self, receipt: HITLCheckpointReceipt, tool_name: str) -> None:
        self.receipt = receipt
        self.tool_name = tool_name
        super().__init__(
            f"[REDHAND_HITL_PAUSED] Tool '{tool_name}' paused awaiting human approval. "
            f"Intervention ID: {receipt.intervention_id}"
        )


# =============================================================================
# 2. EPHEMERAL CREDENTIAL LIFECYCLE & MEMORY ZEROIZATION
# =============================================================================


def get_ephemeral_gcp_token() -> str | None:
    """Retrieves the active single-use GCP OAuth2 access token for the current tool call."""
    return _ephemeral_gcp_token.get()


def get_ephemeral_aws_credentials() -> dict[str, str] | None:
    """Retrieves the active downscoped AWS session credentials for the current tool call."""
    return _ephemeral_aws_creds.get()


def set_reasoning_context(
    *,
    thought: str | None = None,
    trace_id: str | None = None,
    parent_span_id: str | None = None,
    session_id: UUID | None = None,
) -> None:
    """
    Updates coroutine-scoped reasoning context variables. Used by LangChain,
    CrewAI, and MCP adapters to link an agent's preceding Thought to its Action.
    """
    if thought is not None:
        _current_agent_thought.set(thought)
    if trace_id is not None:
        _current_trace_id.set(trace_id)
    if parent_span_id is not None:
        _current_parent_span_id.set(parent_span_id)
    if session_id is not None:
        _current_session_id.set(session_id)


def _scrub_secret_string(secret: str) -> None:
    """Best-effort memory zeroization for sensitive strings in CPython heap."""
    try:
        if sys_refcount := ctypes.c_long.from_address(id(secret)).value:
            if sys_refcount <= 3:
                str_len = len(secret)
                header_size = sys.getsizeof("") - 1
                ctypes.memset(id(secret) + header_size, 0, str_len)
    except Exception:
        pass


@contextmanager
def _ephemeral_token_environment(
    token: str,
    env_var_name: str = "CLOUDSDK_AUTH_ACCESS_TOKEN",
):
    ctx_token = _ephemeral_gcp_token.set(token)
    previous_env_val = os.environ.get(env_var_name)
    os.environ[env_var_name] = token
    try:
        yield
    finally:
        _ephemeral_gcp_token.reset(ctx_token)
        if previous_env_val is None:
            os.environ.pop(env_var_name, None)
        else:
            os.environ[env_var_name] = previous_env_val
        _scrub_secret_string(token)


@contextmanager
def _ephemeral_aws_environment(aws_creds: AWSEphemeralTokenMintResponse):
    creds_dict = {
        "AWS_ACCESS_KEY_ID": aws_creds.access_key_id,
        "AWS_SECRET_ACCESS_KEY": aws_creds.secret_access_key,
        "AWS_SESSION_TOKEN": aws_creds.session_token,
    }
    ctx_token = _ephemeral_aws_creds.set(creds_dict)
    prev_env = {k: os.environ.get(k) for k in creds_dict}
    for k, v in creds_dict.items():
        os.environ[k] = v
    try:
        yield
    finally:
        _ephemeral_aws_creds.reset(ctx_token)
        for k, prev_v in prev_env.items():
            if prev_v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev_v
        _scrub_secret_string(aws_creds.secret_access_key)
        _scrub_secret_string(aws_creds.session_token)


# =============================================================================
# 3. HELPER UTILITIES
# =============================================================================


def _bind_tool_arguments(func: Callable[..., Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
    sig = inspect.signature(func)
    bound = sig.bind_partial(*args, **kwargs)
    bound.apply_defaults()
    serialized: dict[str, Any] = {}
    for k, v in bound.arguments.items():
        if k in ("self", "cls"):
            continue
        try:
            json.dumps(v)
            serialized[k] = v
        except (TypeError, OverflowError):
            serialized[k] = repr(v)
    return serialized


def _compute_state_checksum(state_dict: dict[str, Any]) -> str:
    canonical_bytes = json.dumps(state_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def _resolve_resource_template(
    template: str | None,
    bound_args: dict[str, Any],
) -> str | None:
    if not template:
        return None
    try:
        return template.format(**bound_args)
    except KeyError as exc:
        logger.warning("Failed to interpolate argument %s into resource URI '%s'", exc, template)
        return template


# =============================================================================
# 4. THE @guard INTERCEPTOR DECORATOR
# =============================================================================


def guard(
    *,
    tool_name: str | None = None,
    risk_tier: RiskTier = RiskTier.READ_ONLY,
    failure_mode: FailureMode = FailureMode.FAIL_OPEN,
    target_cloud_resource: str | None = None,
    gcp_permissions: list[str] | None = None,
    iam_condition_expression: str | None = None,
    token_env_var: str = "CLOUDSDK_AUTH_ACCESS_TOKEN",
    aws_role_arn: str | None = None,
    aws_resource_arn: str | None = None,
    aws_actions: list[str] | None = None,
    aws_duration_seconds: int = 900,
    resume_webhook_url: str | HttpUrl | None = None,
    notification_webhook_url: str | HttpUrl | None = None,
    state_getter: Callable[[], dict[str, Any]] | None = None,
    raise_on_block: bool = False,
    raise_on_hitl: bool = False,
    firewall: FirewallEngine | None = None,
    client: RedHandClient | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorates an agent tool (LangChain, CrewAI, MCP, or native Python) with
    RedHand Runtime Protection, Multi-Cloud Ephemeral IAM, and Fail-Safe Resilience.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        resolved_tool_name = tool_name or func.__name__
        is_coroutine = inspect.iscoroutinefunction(func)

        async def _execute_guarded_async(*args: P.args, **kwargs: P.kwargs) -> Any:
            active_firewall = firewall or get_default_firewall()
            active_client = client or get_default_client()

            session_id = _current_session_id.get()
            trace_id = _current_trace_id.get() or secrets.token_hex(16)
            span_id = secrets.token_hex(8)
            parent_span_id = _current_parent_span_id.get()
            agent_thought = _current_agent_thought.get()
            occurred_at = datetime.now(timezone.utc)

            bound_args = _bind_tool_arguments(func, *args, **kwargs)
            resolved_resource = _resolve_resource_template(target_cloud_resource, bound_args)
            resolved_aws_resource = _resolve_resource_template(aws_resource_arn, bound_args)

            # -----------------------------------------------------------------
            # MODULE 1: In-Memory Semantic Firewall (<50ms budget) with Fail-Safe
            # -----------------------------------------------------------------
            try:
                fw_result = active_firewall.evaluate(
                    tool_name=resolved_tool_name,
                    tool_arguments=bound_args,
                    agent_thought=agent_thought,
                )
            except Exception as fw_exc:
                logger.error("Firewall evaluation error on '%s': %s", resolved_tool_name, fw_exc)
                if failure_mode == FailureMode.FAIL_OPEN and risk_tier == RiskTier.READ_ONLY:
                    logger.warning("[REDHAND_FAIL_OPEN_TRIGGERED] Proceeding under FAIL_OPEN policy.")
                    fw_result = FirewallEvaluationResult(
                        verdict=FirewallVerdict.FLAGGED,
                        latency_ms=0.0,
                        finding=SecurityFindingPayload(
                            event_type=SecurityEventType.ANOMALOUS_TOKEN_VELOCITY,
                            severity=SeverityLevel.LOW,
                            verdict=FirewallVerdict.FLAGGED,
                            detector_tier="fail_open_fallback",
                            confidence_score=0.0,
                            firewall_latency_ms=0.0,
                            mitigation_action=f"Fail-open policy permitted '{resolved_tool_name}' after internal check degradation.",
                        ),
                    )
                else:
                    raise RedHandSecurityError(
                        finding=SecurityFindingPayload(
                            event_type=SecurityEventType.PROMPT_INJECTION_INDIRECT,
                            severity=SeverityLevel.CRITICAL,
                            verdict=FirewallVerdict.BLOCKED,
                            detector_tier="fail_closed_guard",
                            confidence_score=1.0,
                            firewall_latency_ms=0.0,
                            mitigation_action=f"Fail-closed policy blocked '{resolved_tool_name}': {fw_exc}",
                        ),
                        span_id=span_id,
                    ) from fw_exc

            if fw_result.verdict == FirewallVerdict.BLOCKED and fw_result.finding is not None:
                blocked_span = TraceSpanItem(
                    session_id=session_id,
                    trace_id=trace_id,
                    span_id=span_id,
                    parent_span_id=parent_span_id,
                    step_type=StepType.ACTION,
                    thought_content=agent_thought,
                    tool_name=resolved_tool_name,
                    tool_arguments=bound_args,
                    tool_risk_tier=risk_tier,
                    firewall_verdict=FirewallVerdict.BLOCKED,
                    firewall_latency_ms=fw_result.latency_ms,
                    occurred_at=occurred_at,
                    security_finding=fw_result.finding,
                )
                await active_client.flush_spans([blocked_span])

                if raise_on_block:
                    raise RedHandSecurityError(finding=fw_result.finding, span_id=span_id)

                return {
                    "status": "blocked_by_redhand_firewall",
                    "span_id": span_id,
                    "event_type": fw_result.finding.event_type.value,
                    "reason": fw_result.finding.mitigation_action,
                    "instruction": "Do NOT retry this tool call with similar inputs.",
                }

            # -----------------------------------------------------------------
            # MODULE 3: Execution Blast Radius Circuit Breaker (HITL Pause)
            # -----------------------------------------------------------------
            if risk_tier in (RiskTier.STATE_MUTATION, RiskTier.DESTRUCTIVE, RiskTier.CRITICAL):
                agent_state = state_getter() if state_getter else {"tool_arguments": bound_args}
                checksum = _compute_state_checksum(agent_state)
                effective_resume_url = (
                    resume_webhook_url
                    or active_client.default_resume_webhook_url
                    or "https://api.redhand.internal/v1/hitl/noop-callback"
                )

                checkpoint_payload = HITLCheckpointPayload(
                    proposed_tool_name=resolved_tool_name,
                    proposed_tool_arguments=bound_args,
                    target_cloud_resource=resolved_resource or resolved_aws_resource,
                    requested_iam_permissions=(gcp_permissions or []) + (aws_actions or []),
                    agent_justification=agent_thought,
                    serialized_agent_state=agent_state,
                    state_checksum=checksum,
                    resume_webhook_url=HttpUrl(str(effective_resume_url)),
                    notification_webhook_url=(
                        HttpUrl(str(notification_webhook_url))
                        if notification_webhook_url
                        else None
                    ),
                )

                hitl_finding = SecurityFindingPayload(
                    event_type=SecurityEventType.HITL_CIRCUIT_TRIPPED,
                    severity=(
                        SeverityLevel.CRITICAL
                        if risk_tier in (RiskTier.DESTRUCTIVE, RiskTier.CRITICAL)
                        else SeverityLevel.HIGH
                    ),
                    verdict=FirewallVerdict.HITL_PAUSED,
                    detector_tier="tier0_blast_radius_gate",
                    confidence_score=1.0,
                    firewall_latency_ms=fw_result.latency_ms,
                    matched_rule_id=f"risk_tier:{risk_tier.value}",
                    mitigation_action=f"Execution of '{resolved_tool_name}' ({risk_tier.value}) halted pending operator approval.",
                )

                paused_span = TraceSpanItem(
                    session_id=session_id,
                    trace_id=trace_id,
                    span_id=span_id,
                    parent_span_id=parent_span_id,
                    step_type=StepType.ACTION,
                    thought_content=agent_thought,
                    tool_name=resolved_tool_name,
                    tool_arguments=bound_args,
                    tool_risk_tier=risk_tier,
                    firewall_verdict=FirewallVerdict.HITL_PAUSED,
                    firewall_latency_ms=fw_result.latency_ms,
                    occurred_at=occurred_at,
                    security_finding=hitl_finding,
                    hitl_checkpoint=checkpoint_payload,
                )

                ingest_resp = await active_client.flush_spans([paused_span])
                receipt = (
                    ingest_resp.hitl_checkpoints[0]
                    if ingest_resp and ingest_resp.hitl_checkpoints
                    else HITLCheckpointReceipt(
                        span_id=span_id,
                        intervention_id=uuid4(),
                        status="pending",
                        expires_at=datetime.now(timezone.utc),
                    )
                )

                if raise_on_hitl:
                    raise RedHandHITLPausedError(receipt=receipt, tool_name=resolved_tool_name)

                return {
                    "status": "hitl_approval_pending",
                    "intervention_id": str(receipt.intervention_id),
                    "span_id": receipt.span_id,
                    "tool_name": resolved_tool_name,
                    "risk_tier": risk_tier.value,
                    "expires_at": receipt.expires_at.isoformat(),
                    "message": f"Execution of '{resolved_tool_name}' paused awaiting approval.",
                }

            # -----------------------------------------------------------------
            # MODULE 2: Multi-Cloud Ephemeral IAM (GCP STS + AWS STS)
            # -----------------------------------------------------------------
            minted_gcp_token: EphemeralTokenMintResponse | None = None
            minted_aws_token: AWSEphemeralTokenMintResponse | None = None

            if resolved_resource and gcp_permissions:
                minted_gcp_token = await active_client.mint_ephemeral_gcp_token(
                    trace_id=trace_id,
                    span_id=span_id,
                    tool_name=resolved_tool_name,
                    target_resource=resolved_resource,
                    permissions=gcp_permissions,
                    condition_expression=iam_condition_expression,
                )

            if aws_role_arn and resolved_aws_resource and aws_actions:
                minted_aws_token = await active_client.mint_ephemeral_aws_token(
                    trace_id=trace_id,
                    span_id=span_id,
                    tool_name=resolved_tool_name,
                    role_arn=aws_role_arn,
                    target_resource_arn=resolved_aws_resource,
                    actions=aws_actions,
                    duration_seconds=aws_duration_seconds,
                )

            # -----------------------------------------------------------------
            # STEP 4: Execute Tool with Single-Use Token & Memory Zeroization
            # -----------------------------------------------------------------
            exec_start = time.perf_counter()
            token_jti = (
                minted_gcp_token.token_jti
                if minted_gcp_token
                else (minted_aws_token.token_jti if minted_aws_token else None)
            )

            try:
                if minted_gcp_token:
                    with _ephemeral_token_environment(
                        token=minted_gcp_token.access_token,
                        env_var_name=token_env_var,
                    ):
                        result = (
                            await func(*args, **kwargs)
                            if is_coroutine
                            else await asyncio.to_thread(func, *args, **kwargs)
                        )
                    _scrub_secret_string(minted_gcp_token.access_token)
                    minted_gcp_token.access_token = "[REDACTED_GCP_TOKEN]"
                elif minted_aws_token:
                    with _ephemeral_aws_environment(minted_aws_token):
                        result = (
                            await func(*args, **kwargs)
                            if is_coroutine
                            else await asyncio.to_thread(func, *args, **kwargs)
                        )
                else:
                    result = (
                        await func(*args, **kwargs)
                        if is_coroutine
                        else await asyncio.to_thread(func, *args, **kwargs)
                    )
            finally:
                exec_latency_ms = round((time.perf_counter() - exec_start) * 1000.0, 2)

            action_span = TraceSpanItem(
                session_id=session_id,
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                step_type=StepType.ACTION,
                thought_content=agent_thought,
                tool_name=resolved_tool_name,
                tool_arguments=bound_args,
                tool_risk_tier=risk_tier,
                firewall_verdict=fw_result.verdict,
                firewall_latency_ms=fw_result.latency_ms,
                execution_latency_ms=exec_latency_ms,
                ephemeral_token_jti=token_jti,
                occurred_at=occurred_at,
                security_finding=fw_result.finding,
            )

            active_client.enqueue_span(action_span)
            return result

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, _execute_guarded_async(*args, **kwargs))
                    return future.result()
            return asyncio.run(_execute_guarded_async(*args, **kwargs))

        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            return await _execute_guarded_async(*args, **kwargs)

        return async_wrapper if is_coroutine else sync_wrapper  # type: ignore[return-value]

    return decorator
