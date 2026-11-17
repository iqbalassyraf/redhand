"""
What the incident view returns (Phase 4.5 B3). Only fields each source's own screen already shows: never a call payload, an argument
value or key, a token id, a honeytoken value, or an audit row's details (a destination change stores the full host there).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

ItemKind = Literal["refusal", "error", "activity", "finding", "trip", "action"]


class TimelineAgent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    name: str
    status: str


class TimelineItem(BaseModel):
    """One moment in the agent's story. Which fields are set depends on `kind`; the others stay empty."""

    model_config = ConfigDict(extra="forbid")

    at: datetime
    kind: ItemKind
    # refusal, error (Black Box)
    seq: int | None = None
    tool_name: str = ""
    server: str = ""
    reasons: list[str] = Field(default_factory=list, description="The gateway's own fixed wording, as on the Black Box page.")
    # activity (hourly roll-up)
    calls: int | None = None
    refused: int | None = None
    # finding (Radar)
    finding_id: UUID | None = None
    rule_id: str = ""
    finding_kind: str = ""
    confidence: str = ""
    review_status: str = ""
    occurrences: int | None = None
    # trip (honeytokens and decoy tools)
    trip_kind: str = ""
    seen_in: str = ""
    # action (control audit)
    action: str = ""
    reason: str | None = None
    automatic: bool | None = Field(default=None, description="True when RedHand acted by itself (the fixed system actor).")
    organization_wide: bool = Field(default=False, description="An action on every agent of the organization (freeze all, Safe Mode for all).")
    in_effect_at_registration: bool = Field(
        default=False,
        description="Safe Mode for every agent, turned on before this agent was registered and still on then: the one older organization-wide "
        "item shown, because it restricted this agent from its start.",
    )


class TimelineResponse(BaseModel):
    agent: TimelineAgent
    items: list[TimelineItem]
    next_before: datetime | None = Field(default=None, description="Pass as `before` to read the next (older) page.")
