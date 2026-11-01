"""
RedHand SDK - Shared Wire Contracts & Pydantic Models
File: packages/redhand-sdk/src/redhand_sdk/models.py

Mirrors the exact schema expected by `redhand-core`'s `/v1/telemetry/ingest`
and `/v1/iam/mint` endpoints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


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


class FailureMode(str, Enum):
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


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


class SecurityFindingPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: SecurityEventType
    severity: SeverityLevel
    verdict: FirewallVerdict
    detector_tier: str = Field(..., min_length=2, max_length=64)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    firewall_latency_ms: float = Field(..., ge=0.0)
    trigger_snippet: str | None = Field(default=None, max_length=2048)
    matched_rule_id: str | None = Field(default=None, max_length=128)
    mitigation_action: str = Field(..., max_length=512)


class HITLCheckpointPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposed_tool_name: str = Field(..., min_length=1, max_length=256)
    proposed_tool_arguments: dict[str, Any] = Field(default_factory=dict)
    target_cloud_resource: str | None = None
    requested_iam_permissions: list[str] = Field(default_factory=list)
    agent_justification: str | None = Field(default=None, max_length=4096)
    serialized_agent_state: dict[str, Any]
    state_checksum: str = Field(..., min_length=64, max_length=64)
    resume_webhook_url: HttpUrl
    notification_webhook_url: HttpUrl | None = None
    ttl_seconds: int = Field(default=3600, ge=60, le=604800)


class TraceSpanItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: UUID
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


class TelemetryBatchIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sdk_version: str = "0.1.0"
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
    server_timestamp: datetime


class EphemeralTokenMintResponse(BaseModel):
    access_token: str
    token_jti: str
    issued_token_type: str
    token_type: str = "Bearer"
    expires_at: datetime
    applied_access_boundary: dict[str, Any]
    mint_latency_ms: float


class AWSEphemeralTokenMintResponse(BaseModel):
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    token_jti: str
    applied_session_policy: dict[str, Any]
    mint_latency_ms: float

