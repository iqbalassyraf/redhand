"""
Models for the per-agent destination allowlist (Phase 4 M7, docs/plans/phase4-m7-destination-allowlist.md).

An allowed destination is one exact, normalized host (see `hosts.py`). The list belongs to one agent, is capped at 100 entries and is only
read by the gateway, which compares the web and email addresses an agent wrote into a tool call with it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from redhand_core.passports.models import MAX_REASON_LENGTH

DestinationMode = Literal["off", "observe", "enforce"]
MAX_ENTRIES = 100
MAX_HOST_INPUT = 300  # what a person may type; the stored host is at most 253 characters


class DestinationEntry(BaseModel):
    id: UUID
    host: str
    created_at: datetime


class DestinationCapabilities(BaseModel):
    """What the signed-in operator may do, so the UI hides buttons the server would refuse. The server enforces it anyway."""

    can_change: bool


class DestinationSettingsResponse(BaseModel):
    destination_mode: DestinationMode
    destination_mode_changed_at: datetime | None = None
    entries: list[DestinationEntry]
    max_entries: int = MAX_ENTRIES
    last_7_days: dict[str, Any]
    capabilities: DestinationCapabilities


class DestinationAddRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=MAX_HOST_INPUT, description="A host name or address only: no scheme, path or port.")
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required: an allowed destination widens what this agent may send data to.")


class DestinationAddResponse(BaseModel):
    id: UUID
    host: str = Field(description="The host as stored (lower case, punycode, dotted IPv4, compressed IPv6).")
    added: bool = Field(description="False when the host was already on the list.")


class DestinationRemoveResponse(BaseModel):
    removed: bool


class DestinationModeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination_mode: DestinationMode
    expected_mode: DestinationMode = Field(description="The mode the caller saw; a different current mode is a conflict.")
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required to turn enforcement on (it refuses calls) or to turn the check off.")
