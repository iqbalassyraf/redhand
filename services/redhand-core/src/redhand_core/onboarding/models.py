"""Request and response models for onboarding (Phase 4.5 D1): sign-up codes, organization creation, member invites, members. No model carries a code
hash or a token hash; a plaintext code or token appears only in the response that creates it."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt

CODE_PREFIX = "rh_inv_"
INVITE_PREFIX = "rh_join_"
CODE_PATTERN = r"^rh_inv_[A-Za-z0-9_-]{20,64}$"
INVITE_PATTERN = r"^rh_join_[A-Za-z0-9_-]{20,64}$"
SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$"

InvitableRole = Literal["admin", "security_operator", "viewer"]
MemberRole = Literal["owner", "admin", "security_operator", "viewer"]
InviteState = Literal["pending", "used", "revoked", "expired"]


class CreateOrganizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    slug: str | None = Field(default=None, pattern=SLUG_PATTERN, description="Optional. Made from the name when omitted.")
    code: str = Field(pattern=CODE_PATTERN, description="A single-use sign-up code issued by the platform owner.")


class CreateOrganizationResponse(BaseModel):
    organization_id: UUID
    slug: str
    role: Literal["owner"] = "owner"


class InviteCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: InvitableRole
    expires_in_days: StrictInt = Field(default=7, ge=1, le=30)


class InviteView(BaseModel):
    id: UUID
    role: InvitableRole
    state: InviteState
    created_at: datetime | None
    expires_at: datetime | None


class InviteCreated(BaseModel):
    token: str = Field(description="Shown once. Send it to the person; RedHand keeps only a hash.")
    join_path: str = Field(description="Append to the dashboard address: the page that accepts the invite.")
    invite: InviteView


class InviteList(BaseModel):
    invites: list[InviteView]
    max_pending: int = 20


class InviteRevokeResponse(BaseModel):
    id: UUID
    changed: bool


class AcceptInviteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(pattern=INVITE_PATTERN)


class AcceptInviteResponse(BaseModel):
    organization_id: UUID
    role: InvitableRole


class MemberView(BaseModel):
    user_id: UUID
    email: str | None
    role: MemberRole
    joined_at: datetime | None


class MemberList(BaseModel):
    members: list[MemberView]


class SetRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: MemberRole
    confirm: bool = Field(default=False, description="Required to give the owner role.")


class SetRoleResponse(BaseModel):
    user_id: UUID
    changed: bool
    role: MemberRole


class RemoveMemberResponse(BaseModel):
    user_id: UUID
    removed: bool


class SignupCodeRequest(BaseModel):
    """Issued by the platform owner with the internal service token (scripts/issue_signup_code.py), never from the dashboard."""

    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=200)
    expires_in_days: StrictInt = Field(default=14, ge=1, le=90)


class SignupCodeCreated(BaseModel):
    code: str = Field(description="Shown once.")
    expires_at: datetime


class MeResponse(BaseModel):
    """Who the signed-in person is and what they may do: the dashboard uses it to show only the actions their role allows (the server still decides)."""

    user_id: UUID
    email: str | None
    organization_id: UUID
    organization_name: str
    role: MemberRole
    # The address name, so the owner's delete screen can ask for it to be typed back (not secret: it is chosen at sign-up and shown to members).
    organization_slug: str = ""
    # Set while a deletion request is pending (the end of the 7-day grace period); every page shows a banner then.
    deletion_purge_after: datetime | None = None
