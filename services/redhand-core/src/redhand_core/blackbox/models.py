"""
Pydantic models for the Black Box Recorder: the gateway's ingest batch, and what the dashboard reads
back. Argument values and tool results are never part of these models in Phase 3 M1 (payload capture
ships in M2); only metadata the gateway's existing audit record already carries
(agentwall/src/telemetry/audit_logger.py) crosses this boundary.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from redhand_core.passports.models import MAX_REASON_LENGTH

Decision = Literal["ALLOW", "BLOCK", "ERROR"]

MAX_ITEMS_PER_BATCH = 500
INSTANCE_ID_PATTERN = r"^[A-Za-z0-9-]{8,64}$"
MAX_REASONS = 10
MAX_ARGUMENT_KEYS = 50


MAX_EXCERPT_CHARS = 2048


class PayloadExcerpt(BaseModel):
    """A redacted, size-capped excerpt of a tool call's arguments or result, built by the gateway (never by
    a client): compact JSON text, cut to at most 2 KB AFTER redaction. Only stored when the organization
    turned payload capture on (record_events() decides that, not the gateway)."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(max_length=MAX_EXCERPT_CHARS)
    truncated: StrictBool
    original_bytes: int = Field(ge=0, le=100_000_000)


class GatewayEventItem(BaseModel):
    """One tool call the gateway allowed, refused or failed to forward. Mirrors
    agentwall.telemetry.audit_logger.AuditRecord, minus raw content."""

    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    occurred_at: datetime
    gateway_instance: str = Field(min_length=1, max_length=64)
    server: str = Field(default="", max_length=128)
    method: str = Field(min_length=1, max_length=64)
    tool_name: str = Field(default="", max_length=128)
    decision: Decision
    reasons: list[str] = Field(default_factory=list, max_length=MAX_REASONS)
    upstream_status: int | None = None
    latency_ms: float | None = None
    argument_keys: list[str] = Field(default_factory=list, max_length=MAX_ARGUMENT_KEYS)
    arguments_sha256: str = ""
    result_size_bytes: int | None = None
    redaction_count: int = 0
    credential_jti: str | None = None
    arguments_redacted: PayloadExcerpt | None = None
    result_excerpt: PayloadExcerpt | None = None


class EventIngestRequest(BaseModel):
    """One batch is one organization: the chain is per-organization and each append locks that
    organization's chain head, so the gateway's recorder groups its buffer by organization before
    flushing (agentwall/src/gateway/recorder.py) rather than mixing tenants in one call. The
    organization claimed here is still re-checked per item against the agent's real organization
    inside record_events(): a wrong or stale value here only causes rejections, never a cross-tenant
    write."""

    model_config = ConfigDict(extra="forbid")

    instance_id: str = Field(pattern=INSTANCE_ID_PATTERN)
    batch_id: UUID
    organization_id: UUID
    items: list[GatewayEventItem] = Field(min_length=1, max_length=MAX_ITEMS_PER_BATCH)


class EventIngestResponse(BaseModel):
    accepted: int
    rejected: int


class BlackBoxEventView(BaseModel):
    seq: int
    agent_id: UUID
    agent_name: str | None = None
    occurred_at: datetime
    server: str
    method: str
    tool_name: str
    decision: Decision
    reasons: list[str]
    upstream_status: int | None
    latency_ms: float | None
    argument_keys: list[str]


class BlackBoxTimelineResponse(BaseModel):
    events: list[BlackBoxEventView]
    next_before_seq: int | None = Field(
        default=None, description="Pass as `before_seq` to fetch the next, older page; null on the last page."
    )


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_seq: int = Field(ge=1)
    to_seq: int = Field(ge=1)


class VerifyResponse(BaseModel):
    ok: bool
    checked: int = 0
    broken_seq: int | None = None
    reason: str | None = None


MIN_RETENTION_DAYS, MAX_RETENTION_DAYS = 7, 90
MIN_PAYLOAD_RETENTION_DAYS, MAX_PAYLOAD_RETENTION_DAYS = 1, 30


class BlackBoxCapabilities(BaseModel):
    """What the caller's role allows, computed by the server. It exists so the dashboard can hide buttons it
    would be refused; the server still enforces every action, so ignoring this field grants nothing."""

    can_manage: bool = Field(description="Change retention or turn payload capture on (admin).")
    can_turn_capture_off: bool
    can_view_payloads: bool
    can_export: bool
    can_export_payloads: bool


class BlackBoxSettingsResponse(BaseModel):
    """The organization's Black Box settings. `capabilities` is filled on GET /v1/blackbox/settings."""

    retention_days: int
    payload_retention_days: int
    payload_capture_enabled: bool
    changed: bool
    capabilities: BlackBoxCapabilities | None = None


class EventPayloadResponse(BaseModel):
    """The stored (redacted) payload of one event. Either field is null when nothing was captured."""

    seq: int
    arguments_redacted: PayloadExcerpt | None
    result_excerpt: PayloadExcerpt | None


class BlackBoxRetentionRequest(BaseModel):
    """New retention periods, in days. Both are required so the request states the full intent."""

    model_config = ConfigDict(extra="forbid")

    retention_days: StrictInt = Field(ge=MIN_RETENTION_DAYS, le=MAX_RETENTION_DAYS)
    payload_retention_days: StrictInt = Field(ge=MIN_PAYLOAD_RETENTION_DAYS, le=MAX_PAYLOAD_RETENTION_DAYS)
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(
        default=False,
        description="Required for any change: a shorter retention deletes events at the next daily purge, "
        "a longer one keeps more data.",
    )


class PayloadCaptureRequest(BaseModel):
    """Turn payload capture on or off for the organization."""

    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(
        default=False,
        description="Required to turn capture ON: from then on redacted excerpts of tool call arguments "
        "and results are stored. Turning it off needs no confirmation.",
    )


class ClearPayloadsRequest(BaseModel):
    """Delete every captured payload of the organization now. The events and the hash chain stay."""

    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required: this cannot be undone.")


class ClearPayloadsResponse(BaseModel):
    cleared: int = Field(description="How many events had a payload removed.")
