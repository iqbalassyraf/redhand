"""
RedHand Core - Telemetry & Security Event Ingestion Router
File: services/redhand-core/src/redhand_core/routers/telemetry.py

Provides the wire contract and ingestion pipeline bridging `redhand-sdk`
and `redhand-core` on GCP Cloud Run.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator
from supabase import AsyncClient

from redhand_core.net.outbound import OutboundBlockedError, check_url, insecure_webhooks_allowed
from redhand_core.passports.models import effective_status, utcnow
from redhand_core.services.dlp_scrubber import get_dlp_scrubber
from redhand_core.services.metrics import get_metrics
from redhand_core.services.notifications.slack import dispatch_slack_hitl_notification
from redhand_core.services.policy_engine import get_policy_engine
from redhand_core.services.siem_exporter import get_siem_exporter
from redhand_core.telegram.deps import OptionalClientDep
from redhand_core.sdkkeys import service as sdk_keys

logger = logging.getLogger("redhand.core.telemetry")

router = APIRouter(
    prefix="/v1/telemetry",
    tags=["Telemetry & Security Ingestion"],
)


# =============================================================================
# 1. ENUMERATIONS (Mirrors PostgreSQL ENUM types in schema.sql)
# =============================================================================


class StepType(str, Enum):
    OBSERVATION = "observation"
    THOUGHT = "thought"
    ACTION = "action"
    TOOL_RESULT = "tool_result"
    SYSTEM_HALT = "system_halt"


class RiskTier(str, Enum):
    READ_ONLY = "read_only"
    STATE_MUTATION = "state_mutation"
    DESTRUCTIVE = "destructive"
    CRITICAL = "critical"


class FirewallVerdict(str, Enum):
    ALLOW = "allow"
    REDACTED = "redacted"
    FLAGGED = "flagged"
    BLOCKED = "blocked"
    HITL_PAUSED = "hitl_paused"


class SecurityEventType(str, Enum):
    PROMPT_INJECTION_DIRECT = "prompt_injection_direct"
    PROMPT_INJECTION_INDIRECT = "prompt_injection_indirect"
    IAM_SCOPE_VIOLATION = "iam_scope_violation"
    UNREGISTERED_TOOL_INVOCATION = "unregistered_tool_invocation"
    DLP_SECRET_LEAK_PREVENTED = "dlp_secret_leak_prevented"
    ANOMALOUS_TOKEN_VELOCITY = "anomalous_token_velocity"
    HITL_CIRCUIT_TRIPPED = "hitl_circuit_tripped"


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# 2. PYDANTIC WIRE CONTRACTS (Shared Contract with `redhand-sdk`)
# =============================================================================


class SecurityFindingPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: SecurityEventType
    severity: SeverityLevel
    verdict: FirewallVerdict
    detector_tier: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Identifier of the defense layer (e.g., 'tier0_ast', 'tier1_onnx_deberta').",
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Classifier probability or heuristic confidence score [0.0 - 1.0].",
    )
    firewall_latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Execution time of the local security evaluation in milliseconds.",
    )
    trigger_snippet: str | None = Field(
        default=None,
        max_length=2048,
        description="Sanitized snippet of the input/output that triggered the finding.",
    )
    matched_rule_id: str | None = Field(
        default=None,
        max_length=128,
        description="Policy rule ID or signature identifier.",
    )
    mitigation_action: str = Field(
        ...,
        max_length=512,
        description="Human-readable description of the enforcement action taken.",
    )


class HITLCheckpointPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposed_tool_name: str = Field(..., min_length=1, max_length=256)
    proposed_tool_arguments: dict[str, Any] = Field(default_factory=dict)
    target_cloud_resource: str | None = Field(
        default=None,
        description="Full resource URI (e.g., '//storage.googleapis.com/projects/_/buckets/prod').",
    )
    requested_iam_permissions: list[str] = Field(default_factory=list)
    agent_justification: str | None = Field(
        default=None,
        max_length=4096,
        description="The agent's preceding Thought explaining why it needs to run this tool.",
    )
    serialized_agent_state: dict[str, Any] = Field(
        ...,
        description="Checkpointer dictionary (e.g., LangGraph state) required to rehydrate the run.",
    )
    state_checksum: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="Hex-encoded SHA-256 hash of the canonical JSON serialized_agent_state.",
    )
    resume_webhook_url: HttpUrl = Field(
        ...,
        description="Callback endpoint to wake up the agent worker upon human approval.",
    )
    notification_webhook_url: HttpUrl | None = Field(
        default=None,
        description="Optional Slack/PagerDuty webhook override for this specific intervention.",
    )
    @field_validator("resume_webhook_url", "notification_webhook_url")
    @classmethod
    def reject_unsafe_webhook_url(cls, v: HttpUrl | None) -> HttpUrl | None:
        """Refuse at ingest a URL that core would never be allowed to call (static checks only;
        the address is checked again, after DNS, at send time)."""
        if v is None:
            return v
        try:
            check_url(str(v), allow_insecure=insecure_webhooks_allowed())
        except OutboundBlockedError as exc:
            raise ValueError(str(exc)) from None
        return v

    ttl_seconds: int = Field(
        default=3600,
        ge=60,
        le=604800,
        description="Seconds before the paused intervention automatically expires.",
    )


class TraceSpanItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: UUID = Field(..., description="Logical conversation or workflow run UUID.")
    trace_id: str = Field(..., min_length=16, max_length=64)
    span_id: str = Field(..., min_length=8, max_length=32)
    parent_span_id: str | None = Field(default=None, max_length=32)
    step_sequence: int = Field(default=0, ge=0)

    step_type: StepType
    model_provider: str | None = Field(default=None, max_length=64)
    model_name: str | None = Field(default=None, max_length=128)

    observation_payload: dict[str, Any] | None = None
    thought_content: str | None = Field(default=None, max_length=32768)
    tool_name: str | None = Field(default=None, max_length=256)
    tool_arguments: dict[str, Any] | None = None
    tool_risk_tier: RiskTier = RiskTier.READ_ONLY

    firewall_verdict: FirewallVerdict = FirewallVerdict.ALLOW
    firewall_latency_ms: float | None = Field(default=None, ge=0.0)
    execution_latency_ms: float | None = Field(default=None, ge=0.0)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    ephemeral_token_jti: str | None = Field(default=None, max_length=128)

    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    security_finding: SecurityFindingPayload | None = None
    hitl_checkpoint: HITLCheckpointPayload | None = None

    @field_validator("occurred_at")
    @classmethod
    def ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @model_validator(mode="after")
    def validate_step_invariants(self) -> TraceSpanItem:
        if self.step_type == StepType.ACTION and not self.tool_name:
            raise ValueError("`tool_name` is required when `step_type` is 'action'.")
        if self.firewall_verdict == FirewallVerdict.HITL_PAUSED and not self.hitl_checkpoint:
            raise ValueError(
                "`hitl_checkpoint` payload must be provided when `firewall_verdict` is 'hitl_paused'."
            )
        if self.firewall_verdict == FirewallVerdict.BLOCKED and not self.security_finding:
            raise ValueError(
                "`security_finding` payload must be provided when `firewall_verdict` is 'blocked'."
            )
        return self


class TelemetryBatchIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sdk_version: str = Field(..., examples=["0.1.0"])
    external_agent_id: str = Field(..., min_length=1, max_length=128)
    agent_name: str = Field(default="Unnamed Agent", max_length=256)
    framework: str = Field(default="custom", max_length=64)
    environment: str = Field(
        default="development",
        pattern="^(development|staging|production)$",
    )
    spans: list[TraceSpanItem] = Field(..., min_length=1, max_length=250)


class HITLCheckpointReceipt(BaseModel):
    span_id: str
    intervention_id: UUID
    status: str = "pending"
    expires_at: datetime


class TelemetryIngestResponse(BaseModel):
    status: str = "accepted"
    organization_id: UUID
    agent_id: UUID
    ingested_spans_count: int
    recorded_security_events_count: int
    hitl_checkpoints: list[HITLCheckpointReceipt] = Field(default_factory=list)
    server_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# 3. DEPENDENCIES (Authentication & Supabase Client Resolution)
# =============================================================================


class AuthenticatedOrgContext(BaseModel):
    organization_id: UUID
    api_key_id: UUID
    siem_webhook_url: str | None = None


async def get_supabase_service_client() -> AsyncClient:
    raise NotImplementedError("Supabase AsyncClient must be overridden in FastAPI app lifespan.")


async def verify_sdk_api_key(
    x_redhand_api_key: Annotated[str, Header(alias="X-RedHand-API-Key")],
    supabase: Annotated[AsyncClient, Depends(get_supabase_service_client)],
) -> AuthenticatedOrgContext:
    if not x_redhand_api_key.startswith("rh_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed RedHand API Key. Expected prefix 'rh_'.",
        )

    key_hash = hashlib.sha256(x_redhand_api_key.encode("utf-8")).hexdigest()

    response = await (
        supabase.table("sdk_api_keys")
        .select("id, organization_id, expires_at, organizations(siem_webhook_url)")
        .eq("key_hash", key_hash)
        .eq("is_active", True)
        .maybe_single()
        .execute()
    )

    record = response.data if response else None
    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked RedHand API Key.",
        )

    if record.get("expires_at"):
        expires_at = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="RedHand API Key has expired.",
            )

    # Per-key limit (C1a): checked after the key is known to be valid, so an invalid key cannot use up a real key's budget.
    if not sdk_keys.allow_ingest(str(record["id"])):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many telemetry batches for this SDK key. Try again in a minute.",
            headers={"Retry-After": "60"},
        )

    org_data = record.get("organizations") or {}
    return AuthenticatedOrgContext(
        organization_id=UUID(record["organization_id"]),
        api_key_id=UUID(record["id"]),
        siem_webhook_url=org_data.get("siem_webhook_url"),
    )


# =============================================================================
# 4. BACKGROUND SIEM & OCSF DISPATCHER
# =============================================================================


def build_ocsf_finding(
    org_id: UUID,
    agent_id: UUID,
    span: TraceSpanItem,
    finding: SecurityFindingPayload,
) -> dict[str, Any]:
    return {
        "class_uid": 2002,
        "class_name": "Application Security Posture Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "time": int(span.occurred_at.timestamp() * 1000),
        "severity": finding.severity.value,
        "action": finding.verdict.value,
        "confidence_score": finding.confidence_score,
        "finding_info": {
            "uid": f"{span.trace_id}:{span.span_id}",
            "title": finding.event_type.value,
            "desc": finding.mitigation_action,
            "analytic": {
                "name": finding.detector_tier,
                "uid": finding.matched_rule_id or "redhand-default-policy",
            },
        },
        "actor": {
            "app_uid": str(agent_id),
            "session": {"uid": str(span.session_id)},
        },
        "unmapped": {
            "organization_id": str(org_id),
            "trace_id": span.trace_id,
            "span_id": span.span_id,
            "tool_name": span.tool_name,
            "firewall_latency_ms": finding.firewall_latency_ms,
        },
    }


async def dispatch_to_siem_background(
    siem_webhook_url: str | None,
    security_event_rows: list[dict[str, Any]],
    supabase_client: Any = None,
) -> None:
    if not siem_webhook_url or not security_event_rows:
        return
    exporter = get_siem_exporter()
    await exporter.export_events(
        siem_webhook_url=siem_webhook_url,
        security_event_rows=security_event_rows,
        supabase_client=supabase_client,
    )


# =============================================================================
# 5. INGESTION ENDPOINT
# =============================================================================


@router.post(
    "/ingest",
    response_model=TelemetryIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest Agent Reasoning Traces, Firewall Verdicts, and HITL Checkpoints",
)
async def ingest_telemetry_batch(
    payload: TelemetryBatchIngestRequest,
    background_tasks: BackgroundTasks,
    auth_ctx: Annotated[AuthenticatedOrgContext, Depends(verify_sdk_api_key)],
    supabase: Annotated[AsyncClient, Depends(get_supabase_service_client)],
    telegram: OptionalClientDep,
) -> TelemetryIngestResponse:

    # Never an upsert: a batch must not rename, re-frame or re-home an existing passport (C1b). A new agent id becomes a reported-only passport
    # with no gateway access until an admin promotes it.
    resolved = await supabase.rpc(
        "telemetry_resolve_agent",
        {
            "p_org": str(auth_ctx.organization_id),
            "p_external": payload.external_agent_id,
            "p_environment": payload.environment,
            "p_name": payload.agent_name,
            "p_framework": payload.framework,
        },
    ).execute()

    agent_record = resolved.data if isinstance(resolved.data, dict) else None
    if not agent_record or "id" not in agent_record:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to resolve or register agent identity.",
        )

    agent_id = UUID(agent_record["id"])
    agent_status = effective_status(
        str(agent_record.get("status")), agent_record.get("expires_at"), datetime.now(timezone.utc)
    )

    if agent_status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent '{payload.external_agent_id}' is currently {agent_status} by RedHand policy.",
        )

    trace_rows: list[dict[str, Any]] = []
    security_event_rows: list[dict[str, Any]] = []
    hitl_rows: list[dict[str, Any]] = []
    hitl_receipts: list[HITLCheckpointReceipt] = []
    scrubber = get_dlp_scrubber()

    for span in payload.spans:
        trace_row_id = uuid4()

        # Run streaming DLP & secret redaction before persistence
        clean_obs, obs_dlp = scrubber.scrub_value(
            span.observation_payload, field_path="observation_payload"
        )
        clean_thought, thought_dlp = scrubber.scrub_text(
            span.thought_content, field_path="thought_content"
        )
        clean_args, args_dlp = scrubber.scrub_value(
            span.tool_arguments, field_path="tool_arguments"
        )
        dlp_detections = [*obs_dlp, *thought_dlp, *args_dlp]

        effective_verdict = span.firewall_verdict.value
        if dlp_detections and effective_verdict == FirewallVerdict.ALLOW.value:
            effective_verdict = FirewallVerdict.REDACTED.value

        metrics = get_metrics()
        metrics.increment_counter("redhand_firewall_evaluations_total", labels={"verdict": effective_verdict})
        if span.firewall_latency_ms:
            metrics.record_histogram("redhand_firewall_latency_seconds", span.firewall_latency_ms / 1000.0)

        trace_rows.append(
            {
                "id": str(trace_row_id),
                "organization_id": str(auth_ctx.organization_id),
                "agent_id": str(agent_id),
                "session_id": str(span.session_id),
                "trace_id": span.trace_id,
                "span_id": span.span_id,
                "parent_span_id": span.parent_span_id,
                "step_sequence": span.step_sequence,
                "step_type": span.step_type.value,
                "model_provider": span.model_provider,
                "model_name": span.model_name,
                "observation_payload": clean_obs,
                "thought_content": clean_thought,
                "tool_name": span.tool_name,
                "tool_arguments": clean_args,
                "tool_risk_tier": span.tool_risk_tier.value,
                "firewall_verdict": effective_verdict,
                "firewall_latency_ms": span.firewall_latency_ms,
                "execution_latency_ms": span.execution_latency_ms,
                "prompt_tokens": span.prompt_tokens,
                "completion_tokens": span.completion_tokens,
                "ephemeral_token_jti": span.ephemeral_token_jti,
                "occurred_at": span.occurred_at.isoformat(),
            }
        )

        security_event_id: UUID | None = None

        # Auto-emit DLP security finding if secrets/PII were scrubbed
        if dlp_detections and not span.security_finding:
            first_dlp = dlp_detections[0]
            span.security_finding = SecurityFindingPayload(
                event_type=SecurityEventType.DLP_SECRET_LEAK_PREVENTED,
                severity=SeverityLevel.HIGH,
                verdict=FirewallVerdict.REDACTED,
                detector_tier="tier0_dlp_scrubber",
                confidence_score=1.0,
                firewall_latency_ms=span.firewall_latency_ms or 0.8,
                trigger_snippet=first_dlp.redacted_preview,
                matched_rule_id=first_dlp.rule_id,
                mitigation_action=(
                    f"Redacted {len(dlp_detections)} sensitive credential/PII pattern(s) "
                    f"({first_dlp.label}) in {first_dlp.field_path} prior to persistence."
                ),
            )

        if span.security_finding:
            security_event_id = uuid4()
            finding = span.security_finding
            ocsf_doc = build_ocsf_finding(
                org_id=auth_ctx.organization_id,
                agent_id=agent_id,
                span=span,
                finding=finding,
            )

            security_event_rows.append(
                {
                    "id": str(security_event_id),
                    "organization_id": str(auth_ctx.organization_id),
                    "agent_id": str(agent_id),
                    "execution_trace_id": str(trace_row_id),
                    "trace_id": span.trace_id,
                    "span_id": span.span_id,
                    "event_type": finding.event_type.value,
                    "severity": finding.severity.value,
                    "verdict": finding.verdict.value,
                    "detector_tier": finding.detector_tier,
                    "confidence_score": finding.confidence_score,
                    "firewall_latency_ms": finding.firewall_latency_ms,
                    "trigger_snippet": finding.trigger_snippet,
                    "matched_rule_id": finding.matched_rule_id,
                    "mitigation_action": finding.mitigation_action,
                    "ocsf_payload": ocsf_doc,
                    "occurred_at": span.occurred_at.isoformat(),
                }
            )

        if span.hitl_checkpoint:
            intervention_id = uuid4()
            cp = span.hitl_checkpoint
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=cp.ttl_seconds)

            policy_engine = get_policy_engine()
            policy_decision = policy_engine.evaluate(
                agent_environment=payload.environment,
                tool_name=cp.proposed_tool_name,
                risk_tier=span.tool_risk_tier.value,
                target_resource=cp.target_cloud_resource,
            )
            req_approvals = max(1, policy_decision.required_approvals)

            hitl_row = {
                "id": str(intervention_id),
                "organization_id": str(auth_ctx.organization_id),
                "agent_id": str(agent_id),
                "execution_trace_id": str(trace_row_id),
                "security_event_id": str(security_event_id) if security_event_id else None,
                "trace_id": span.trace_id,
                "span_id": span.span_id,
                "status": "pending",
                "risk_tier": span.tool_risk_tier.value,
                "proposed_tool_name": cp.proposed_tool_name,
                "proposed_tool_arguments": cp.proposed_tool_arguments,
                "target_cloud_resource": cp.target_cloud_resource,
                "requested_iam_permissions": cp.requested_iam_permissions,
                "agent_justification": cp.agent_justification or span.thought_content,
                "serialized_agent_state": cp.serialized_agent_state,
                "state_checksum": cp.state_checksum,
                "resume_webhook_url": str(cp.resume_webhook_url),
                "notification_webhook_url": (
                    str(cp.notification_webhook_url) if cp.notification_webhook_url else None
                ),
                "required_approvals": req_approvals,
                "approvals": [],
                "policy_rule_id": policy_decision.matched_rule_id,
                "expires_at": expires_at.isoformat(),
            }

            hitl_rows.append(hitl_row)

            if cp.notification_webhook_url:
                background_tasks.add_task(
                    dispatch_slack_hitl_notification,
                    str(cp.notification_webhook_url),
                    {**hitl_row, "agent_name": payload.agent_name},
                )

            hitl_receipts.append(
                HITLCheckpointReceipt(
                    span_id=span.span_id,
                    intervention_id=intervention_id,
                    status="pending",
                    expires_at=expires_at,
                )
            )

    await (
        supabase.table("execution_traces")
        .upsert(trace_rows, on_conflict="organization_id,trace_id,span_id")
        .execute()
    )

    if security_event_rows:
        await supabase.table("security_events").insert(security_event_rows).execute()

    if hitl_rows:
        await supabase.table("hitl_interventions").insert(hitl_rows).execute()

    if security_event_rows and auth_ctx.siem_webhook_url:
        background_tasks.add_task(
            dispatch_to_siem_background,
            auth_ctx.siem_webhook_url,
            security_event_rows,
            supabase,
        )

    background_tasks.add_task(sdk_keys.touch, supabase, auth_ctx.api_key_id)  # "last used", after the reply, at most once a minute

    # Model spend (B4a): count models with no known price (no names), and, when the batch reported model use, compare today's estimate with the
    # agent's dollar limit AFTER the SDK has its reply. Detective only: nothing here can refuse or fail this batch.
    from redhand_core.spend import service as spend_service  # late: spend.service -> passports.service -> auth.operator imports this module

    reported_usage, unpriced_models = spend_service.summarize_batch(trace_rows)
    spend_service.note_unpriced_models(unpriced_models)
    if reported_usage:
        background_tasks.add_task(spend_service.check_spend, supabase, telegram, auth_ctx.organization_id, agent_id, utcnow())
    # Approved models (B4b): models the batch named that are outside a non-empty approved list become findings, also after the reply.
    from redhand_core.approved import service as approved_service  # late, for the same reason

    named_models = approved_service.models_in_batch(trace_rows)
    if named_models:
        background_tasks.add_task(approved_service.check_models, supabase, telegram, auth_ctx.organization_id, agent_id, named_models, utcnow())

    return TelemetryIngestResponse(
        organization_id=auth_ctx.organization_id,
        agent_id=agent_id,
        ingested_spans_count=len(trace_rows),
        recorded_security_events_count=len(security_event_rows),
        hitl_checkpoints=hitl_receipts,
    )

