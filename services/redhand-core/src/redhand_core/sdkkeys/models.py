"""Request and response models for organization SDK keys (Phase 4.5 C1a). No model ever carries a key hash; only the create response carries the plaintext."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt

MAX_ACTIVE_KEYS = 10
DEFAULT_EXPIRY_DAYS = 90
MAX_EXPIRY_DAYS = 365
KeyState = Literal["active", "expired", "revoked"]


class SdkKeyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100, description="What this key is for, for example 'ci pipeline'.")
    expires_in_days: StrictInt = Field(default=DEFAULT_EXPIRY_DAYS, ge=1, le=MAX_EXPIRY_DAYS)


class SdkKeyRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=500)


class SdkKeyView(BaseModel):
    id: UUID
    name: str
    key_prefix: str
    state: KeyState
    created_at: datetime | None
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


class SdkKeyCreated(BaseModel):
    """The only response that carries the plaintext key. It is never stored and cannot be fetched again."""

    secret: str
    key: SdkKeyView
    notice: str = "Copy this key now: RedHand stores only its hash and will never show it again."


class SdkKeyList(BaseModel):
    keys: list[SdkKeyView]
    max_active: int = MAX_ACTIVE_KEYS


class SdkKeyRevokeResponse(BaseModel):
    id: UUID
    changed: bool
