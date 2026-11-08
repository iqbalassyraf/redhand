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

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from redhand_core.passports.models import MAX_REASON_LENGTH

RULE_ID_PATTERN = r"^RAD-(INJ|OUT)-[0-9]{3}$"
Level = Literal["low", "medium", "high"]
FindingKind = Literal["injection", "output"]
Place = Literal["text", "hidden", "decoded"]
Evasion = Literal["invisible", "lookalike", "leet", "encoded", "hidden"]
ReviewStatus = Literal["open", "confirmed", "false_alarm"]
SettableMode = Literal["off", "observe"]
Mode = Literal["off", "observe", "block"]
MAX_ITEMS_PER_REPORT = 20
MAX_NOTE_LENGTH = 300


class FindingItem(BaseModel):
    """One finding as the gateway reports it. The gateway re-derives nothing from the text: it sends only these fields."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(pattern=RULE_ID_PATTERN)
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


class SuppressionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    rule_id: str = Field(pattern=RULE_ID_PATTERN)
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
