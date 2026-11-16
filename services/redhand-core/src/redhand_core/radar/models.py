"""
Models for the Prompt Injection Radar and output checks (Phase 4 M4.2, docs/plans/phase4-m4-plan.md).

A finding NEVER carries the scanned text: it holds a fixed rule id, family, severity, confidence, a coarse place and evasion
tags, all validated here and again in SQL. Anything an operator types (a review note, a suppression reason) is plain text
kept only for the organization's own records.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from redhand_core.passports.models import MAX_REASON_LENGTH

RULE_ID_PATTERN = r"^RAD-(INJ|OUT)-[0-9]{3}$"  # the injection and output rules: scan counts and readiness only know these
FINDING_RULE_PATTERN = r"^RAD-(INJ|OUT|LOOP|DST|MDL)-[0-9]{3}$"  # every rule a finding or a suppression may name
Level = Literal["low", "medium", "high"]
FindingKind = Literal["injection", "output", "loop", "destination", "model"]
RadarKind = Literal["injection", "output"]  # the Radar's own two checks: scan counts and readiness never include loops
Place = Literal["text", "hidden", "decoded", "call"]
LoopMode = Literal["off", "observe", "throttle"]
Evasion = Literal["invisible", "lookalike", "leet", "encoded", "hidden"]
ReviewStatus = Literal["open", "confirmed", "false_alarm"]
SettableMode = Literal["off", "observe"]
Mode = Literal["off", "observe", "block"]
MAX_ITEMS_PER_REPORT = 20
MAX_NOTE_LENGTH = 300


class FindingItem(BaseModel):
    """One finding as the gateway reports it. The gateway re-derives nothing from the text: it sends only these fields."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(pattern=FINDING_RULE_PATTERN)
    kind: FindingKind
    family: str = Field(pattern=r"^[a-z][a-z-]{1,23}$")
    severity: Level
    confidence: Level
    place: Place
    evasion: list[Evasion] = Field(default_factory=list, max_length=5)
    tool_name: str = Field(default="", max_length=128)
    server: str = Field(default="", max_length=63)
    would_block: bool = False
    occurrences: int = Field(default=1, ge=1, le=1000)
    # Destination findings only: the last two labels of the address, never a subdomain (a subdomain can carry the stolen data).
    detail: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9_.:-]+$")


class FindingReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    agent_id: UUID
    items: list[FindingItem] = Field(min_length=1, max_length=MAX_ITEMS_PER_REPORT)


class FindingReportResponse(BaseModel):
    new: int
    coalesced: int
    suppressed: int
    capped: int
    skipped: int
    disabled: int


class FindingView(BaseModel):
    id: UUID
    agent_id: UUID
    agent_name: str | None = None
    rule_id: str
    family: str
    kind: FindingKind
    severity: Level
    confidence: Level
    place: Place
    evasion: list[str]
    tool_name: str
    server_slug: str
    would_block: bool
    occurrences: int
    detail: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    review_status: ReviewStatus
    reviewed_at: datetime | None = None
    review_note: str | None = None


class FindingsResponse(BaseModel):
    findings: list[FindingView]
    next_before: datetime | None = Field(default=None, description="Pass as `before` to read the next (older) page.")


class FindingReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["confirmed", "false_alarm"]
    note: str | None = Field(default=None, max_length=MAX_NOTE_LENGTH)


class FindingReviewResponse(BaseModel):
    review_status: ReviewStatus
    changed: bool


class RadarCapabilities(BaseModel):
    """What the signed-in operator may do, so the UI hides buttons the server would refuse. The server enforces it anyway."""

    can_change_modes: bool
    can_review: bool
    can_suppress: bool


class RadarSettingsResponse(BaseModel):
    radar_mode: Mode
    output_check_mode: Mode
    radar_mode_changed_at: datetime | None = None
    output_check_mode_changed_at: datetime | None = None
    block_available: bool = Field(default=False, description="False until the measured block gate exists (plan section 11.2).")
    last_7_days: dict[str, Any]
    capabilities: RadarCapabilities


class RadarSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    radar_mode: SettableMode
    output_check_mode: SettableMode
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required when a check is turned off.")


class LoopSettingsResponse(BaseModel):
    """Loop detection (Phase 4 M6): how many identical calls in how many seconds count as a loop, and what happens then."""

    loop_mode: LoopMode
    loop_limit: int
    loop_window_seconds: int
    loop_mode_changed_at: datetime | None = None
    last_7_days: dict[str, Any]
    capabilities: RadarCapabilities


class LoopSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    loop_mode: LoopMode
    loop_limit: StrictInt = Field(ge=3, le=1000, description="Identical calls in one window that count as a loop (the limit-th call is flagged).")
    loop_window_seconds: StrictInt = Field(ge=10, le=600)
    expected_mode: LoopMode | None = Field(default=None, description="The mode the caller saw; a different current mode is a conflict.")
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required to turn throttling on (it refuses calls) or to turn detection off.")


class SuppressionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    rule_id: str = Field(pattern=FINDING_RULE_PATTERN)
    days: int = Field(default=30, ge=1, le=90)
    reason: str = Field(min_length=3, max_length=MAX_NOTE_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required: a suppression stops a check from recording findings for this agent.")


class SuppressionView(BaseModel):
    id: UUID
    agent_id: UUID
    agent_name: str | None = None
    rule_id: str
    reason: str
    created_at: datetime
    expires_at: datetime


class SuppressionsResponse(BaseModel):
    suppressions: list[SuppressionView]


class SuppressionCreateResponse(BaseModel):
    id: UUID
    created: bool
    expires_at: datetime


class SuppressionRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=MAX_NOTE_LENGTH)


class SuppressionRevokeResponse(BaseModel):
    revoked: bool


class SelfTestCategory(BaseModel):
    """Counts for one check on the bundled held-out samples. No sample text and no sample ids: held-out misses are never listed."""

    model_config = ConfigDict(extra="forbid")

    category: Literal["injection_indirect", "output_xss", "output_ssrf", "output_path"]
    malicious: int = Field(ge=1)
    benign: int = Field(ge=1)
    detected: int = Field(ge=0)
    false_alarms: int = Field(ge=0)
    detection_low: float = Field(ge=0, le=1)
    detection_high: float = Field(ge=0, le=1)
    false_alarm_low: float = Field(ge=0, le=1)
    false_alarm_high: float = Field(ge=0, le=1)
    hard_benign: int = Field(ge=0)
    hard_false_alarms: int = Field(ge=0)


class GatewaySelfTest(BaseModel):
    """What the gateway answers. Validated here so a malformed or surprising answer is an error, never a result."""

    model_config = ConfigDict(extra="forbid")

    corpus: str = Field(pattern=r"^[0-9a-f]{8,64}$")
    model_enabled: bool
    samples: int = Field(ge=1)
    duration_ms: float = Field(ge=0)
    categories: list[SelfTestCategory] = Field(min_length=1, max_length=8)
    limits: str = Field(max_length=500)


class SelfTestResponse(GatewaySelfTest):
    radar_mode: Mode
    output_check_mode: Mode
    ran_at: datetime


# --- Evidence from real traffic (Phase 4 M4.6b, docs/plans/phase4-m4-6-block-gate.md) ------------------------------------------------

MAX_SCAN_COUNT = 1_000_000
FINGERPRINT_PATTERN = r"^(unknown|[0-9a-f]{16}(\+model)?)$"


class ScanRuleCount(BaseModel):
    """How many scanned results one rule flagged (any confidence) and flagged strongly. Numbers only."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(pattern=RULE_ID_PATTERN)
    flagged: int = Field(ge=0, le=MAX_SCAN_COUNT)
    strong: int = Field(ge=0, le=MAX_SCAN_COUNT)


class ScanCountItem(BaseModel):
    """The gateway's totals for one organization and one check since its last report. No text, no tool name, no agent."""

    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    kind: RadarKind
    scanned: int = Field(ge=0, le=MAX_SCAN_COUNT)
    dropped: int = Field(ge=0, le=MAX_SCAN_COUNT)
    errors: int = Field(ge=0, le=MAX_SCAN_COUNT)
    flagged: int = Field(ge=0, le=MAX_SCAN_COUNT)
    strong: int = Field(ge=0, le=MAX_SCAN_COUNT)
    rules: list[ScanRuleCount] = Field(default_factory=list, max_length=40)


class ScanCountsReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_id: UUID = Field(description="Chosen by the gateway for each report; a report sent again with the same id is counted once.")
    rules_fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    items: list[ScanCountItem] = Field(min_length=1, max_length=50)


class ScanCountsResponse(BaseModel):
    recorded: int
    skipped: int
    duplicate: bool = False


class RuleCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flagged: int = Field(ge=0)
    strong: int = Field(ge=0)


class KindInputs(BaseModel):
    """What the database knows about one check over the window. Read strictly: anything unexpected is an error, never a verdict."""

    model_config = ConfigDict(extra="forbid")

    mode: Mode
    mode_changed_at: datetime
    scanned: int = Field(ge=0)
    dropped: int = Field(ge=0)
    errors: int = Field(ge=0)
    flagged: int = Field(ge=0)
    strong: int = Field(ge=0)
    fingerprints: list[str]
    rules: dict[str, RuleCounts]
    stored_occurrences: dict[str, int]
    strong_open: int = Field(ge=0)
    false_alarm_rules: list[str]
    silences_in_window: int = Field(ge=0)
    max_findings_per_agent_day: int = Field(ge=0)


class ReadinessInputs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    now: datetime
    window_start: datetime
    kinds: dict[RadarKind, KindInputs]


class ReadinessCondition(BaseModel):
    id: str
    name: str
    passed: bool
    detail: str


class ReadinessCheck(BaseModel):
    kind: RadarKind
    label: str
    ready: bool
    scanned: int
    strong: int
    strong_rate: float | None = Field(description="Strong findings per result scanned on this organization's traffic, or null when nothing was scanned.")
    false_alarms_worst_case: int
    false_alarm_upper: float | None
    conditions: list[ReadinessCondition]


class ReadinessResponse(BaseModel):
    """Whether this organization's own traffic has produced enough clean evidence to CONSIDER block mode. It grants nothing."""

    block_available: Literal[False] = False
    window_start: datetime
    window_days: int
    checks: list[ReadinessCheck]
    note: str
