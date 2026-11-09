"""Models for honeytokens, honey tools and trip reports (Phase 3 M3/M4). See docs/adr/0012-honeytokens.md."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from redhand_core.honeytokens.generator import HoneytokenKind
from redhand_core.passports.models import SERVER_SLUG_PATTERN

Action = Literal["alert", "freeze"]
LABEL_PATTERN = r"^[^\x00-\x1f\x7f]{1,64}$"
TOOL_NAME_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{2,63}$"
MAX_ACTIVE_HONEYTOKENS = 50
MAX_ACTIVE_HONEY_TOOLS_PER_AGENT = 5


class HoneytokenCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(pattern=LABEL_PATTERN, description="What the owner calls it, for example 'Decoy prod key in .env'.")
    kind: HoneytokenKind
    action_on_use: Action = Field(
        default="freeze",
        description="When an agent USES it in a tool call (the call is refused). Default: freeze, except for a canary (alert).",
    )
    action_on_read: Action = Field(default="alert", description="When it appears in a tool RESULT (the agent read it).")

    @model_validator(mode="after")
    def _a_canary_does_not_freeze_unless_asked(self) -> "HoneytokenCreateRequest":
        # Decision F-D3 (docs/plans/phase4-m5a-canary.md): anyone who steals a system prompt can replay the canary on purpose, so
        # freezing must be an explicit choice, never the default. Only a field the caller did not send is defaulted.
        if self.kind == "canary" and "action_on_use" not in self.model_fields_set:
            self.action_on_use = "alert"
        return self


class HoneytokenView(BaseModel):
    id: UUID
    label: str
    kind: HoneytokenKind
    hint: str = Field(description="The last four characters, to recognise it. Never the value.")
    action_on_use: Action
    action_on_read: Action
    status: Literal["active", "retired"]
    created_at: datetime
    last_tripped_at: datetime | None
    trip_count: int


class HoneytokenCreated(HoneytokenView):
    value: str = Field(description="The honeytoken value. Shown ONCE: RedHand stores only its digest.")


class HoneyToolCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    server: str = Field(pattern=SERVER_SLUG_PATTERN)
    name: str = Field(pattern=TOOL_NAME_PATTERN)
    description: str = Field(min_length=1, max_length=300)
    action: Action = "alert"


class HoneyToolView(BaseModel):
    id: UUID
    agent_id: UUID
    server: str
    name: str
    description: str
    action: Action
    status: Literal["active", "retired"]
    created_at: datetime
    last_tripped_at: datetime | None
    trip_count: int


class RetireResponse(BaseModel):
    changed: bool


class TripReport(BaseModel):
    """One trip, reported by the gateway (internal). The organization, agent and reference are all re-checked
    against the database in record_trip(); nothing here is trusted."""

    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    trip_id: UUID
    agent_id: UUID
    kind: Literal["honeytoken", "honey_tool"]
    ref_id: UUID
    seen_in: Literal["arguments", "result", "call"]
    tool_name: str = Field(default="", max_length=128)
    server: str = Field(default="", max_length=128)


class TripResponse(BaseModel):
    recorded: bool
