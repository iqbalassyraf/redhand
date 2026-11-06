"""Models for tool pinning (Phase 4 M3). See docs/adr/0014-tool-pinning.md. Text that came from an MCP server is untrusted."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from redhand_core.passports.models import MAX_REASON_LENGTH, SERVER_SLUG_PATTERN

PinMode = Literal["off", "alert", "enforce"]
PinStatus = Literal["pending", "approved", "rejected", "superseded"]
MAX_TOOLS_PER_REPORT = 200


class ObservedTool(BaseModel):
    """One tool version the gateway saw, identified by the hash of its name, description and schema. The description and
    schema are kept (capped) only so the owner can review what changed; rules holds rule ids, never matched text."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    description: str = Field(default="", max_length=2000)
    schema_text: str = Field(default="", max_length=8000, alias="schema")
    rules: list[str] = Field(default_factory=list, max_length=20)


class ObservationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    organization_id: UUID
    server: str = Field(pattern=SERVER_SLUG_PATTERN)
    tools: list[ObservedTool] = Field(min_length=1, max_length=MAX_TOOLS_PER_REPORT)


class ObservationResponse(BaseModel):
    new: int
    changed: int


class ToolPinView(BaseModel):
    id: UUID
    tool_name: str
    status: PinStatus
    change_kind: Literal["new", "changed"]
    description: str
    schema_text: str
    rules: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    approved_description: str | None = Field(default=None, description="What the currently approved version says, to compare against.")
    approved_schema_text: str | None = None


class ToolPinsResponse(BaseModel):
    server_id: UUID
    server_slug: str
    pin_mode: PinMode
    pending_count: int
    pins: list[ToolPinView]


class PinDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)


class PinDecisionResponse(BaseModel):
    status: PinStatus


class ApproveAllRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required: this approves every pending tool on the server.")


class ApproveAllResponse(BaseModel):
    approved: int


class PinModeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: PinMode
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required for any change: off removes the check, enforce can hide tools from agents.")


class PinModeResponse(BaseModel):
    pin_mode: PinMode
    changed: bool
