"""
Onboarding (Phase 4.5 D1): a signed-in person with no organization creates one with a single-use sign-up code or joins one with an invite token; an
admin invites teammates and manages roles. Codes and tokens are 192-bit random, stored only as SHA-256, shown once, never logged. The rules that matter
(single use, expiry, one organization per person, no owner by invite, the last owner stays) live in the database functions; this module generates and
hashes, rate-limits, and turns refusals into the same plain answers whatever the reason.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from redhand_core.auth.operator import AuthenticatedUser, OperatorContext, Role
from redhand_core.onboarding.models import (
    CODE_PREFIX,
    INVITE_PREFIX,
    AcceptInviteResponse,
    CreateOrganizationResponse,
    InviteCreated,
    InviteList,
    InviteRevokeResponse,
    InviteState,
    InviteView,
    MemberList,
    MeResponse,
    MemberView,
    RemoveMemberResponse,
    SetRoleResponse,
    SignupCodeCreated,
)
from redhand_core.passports.service import _conflict, _rpc
from redhand_core.services.metrics import get_metrics
from redhand_core.services.rate_limit import SlidingWindowLimiter

logger = logging.getLogger("redhand.core.onboarding")

HOUR = 3600.0
_user_limiter = SlidingWindowLimiter(window_seconds=HOUR)
_source_limiter = SlidingWindowLimiter(window_seconds=HOUR)
INVITE_COLUMNS = "id,role,token_hash,created_at,expires_at,used_at,revoked_at"

NO_CODE = "That sign-up code cannot be used. It may be wrong, already used or expired."
NO_INVITE = "That invite cannot be used. It may be wrong, already used, revoked or expired."
ALREADY_MEMBER = "This account already belongs to an organization."


def reset_limits_for_tests() -> None:
    global _user_limiter, _source_limiter
    _user_limiter = SlidingWindowLimiter(window_seconds=HOUR)
    _source_limiter = SlidingWindowLimiter(window_seconds=HOUR)


def new_secret(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(24)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def slug_from(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30].strip("-") or "org"
    return f"{base}-{secrets.token_hex(3)}"


def check_rate(user_id: UUID, source: str, per_user: int, per_source: int) -> None:
    """Counted per attempt, before any lookup: guessing codes is limited as a caller, not per code."""
    now = time.monotonic()
    if not _source_limiter.allow(source, per_source, now) or not _user_limiter.allow(str(user_id), per_user, now):
        get_metrics().increment_counter("onboarding_rate_limited_total")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Try again in an hour.", headers={"Retry-After": "3600"})


# --- a person without an organization --------------------------------------------------------------------------------------------------

async def create_organization(supabase: Any, user: AuthenticatedUser, name: str, slug: str | None, code: str, mode: str) -> CreateOrganizationResponse:
    if mode != "invite":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "New organizations cannot be created right now.")
    chosen = slug or slug_from(name)
    data = await _rpc(
        supabase, "control_org_create",
        {"p_user": str(user.user_id), "p_name": name.strip(), "p_slug": chosen, "p_code_hash": sha256(code)},
        not_found_detail="Not found.", conflict_detail="The organization could not be created. Try again.",
    )
    if not isinstance(data, dict) or not data.get("created"):
        reason = data.get("reason") if isinstance(data, dict) else None
        get_metrics().increment_counter("onboarding_total", labels={"event": f"org_refused_{reason or 'unknown'}"})
        if reason == "member":
            raise _conflict(ALREADY_MEMBER)
        if reason == "slug":
            raise _conflict("That address name is taken. Choose another.")
        raise HTTPException(status.HTTP_403_FORBIDDEN, NO_CODE)
    get_metrics().increment_counter("onboarding_total", labels={"event": "org_created"})
    return CreateOrganizationResponse(organization_id=UUID(str(data["organization_id"])), slug=chosen)


async def accept_invite(supabase: Any, user: AuthenticatedUser, token: str) -> AcceptInviteResponse:
    data = await _rpc(
        supabase, "control_member_invite_accept", {"p_user": str(user.user_id), "p_token_hash": sha256(token)},
        not_found_detail="Not found.", conflict_detail="The invite could not be accepted. Try again.",
    )
    if not isinstance(data, dict) or not data.get("joined"):
        reason = data.get("reason") if isinstance(data, dict) else None
        get_metrics().increment_counter("onboarding_total", labels={"event": f"invite_refused_{reason or 'unknown'}"})
        if reason == "member":
            raise _conflict(ALREADY_MEMBER)
        raise HTTPException(status.HTTP_403_FORBIDDEN, NO_INVITE)
    get_metrics().increment_counter("onboarding_total", labels={"event": "invite_accepted"})
    return AcceptInviteResponse(organization_id=UUID(str(data["organization_id"])), role=data["role"])


# --- platform owner: sign-up codes -----------------------------------------------------------------------------------------------

async def issue_signup_code(supabase: Any, note: str | None, expires_in_days: int, now: datetime) -> SignupCodeCreated:
    code = new_secret(CODE_PREFIX)
    expires_at = now + timedelta(days=expires_in_days)
    await supabase.table("signup_codes").insert({"code_hash": sha256(code), "note": note, "expires_at": expires_at.isoformat()}).execute()
    get_metrics().increment_counter("onboarding_total", labels={"event": "code_issued"})
    return SignupCodeCreated(code=code, expires_at=expires_at)


# --- admins: invites and members -------------------------------------------------------------------------------------------------

def _invite_view(row: dict[str, Any], now: datetime) -> InviteView:
    state: InviteState
    if row.get("used_at"):
        state = "used"
    elif row.get("revoked_at"):
        state = "revoked"
    else:
        expires = _parse(row.get("expires_at"))
        state = "expired" if expires is not None and expires <= now else "pending"
    return InviteView(id=UUID(str(row["id"])), role=row["role"], state=state, created_at=_parse(row.get("created_at")), expires_at=_parse(row.get("expires_at")))


async def create_invite(supabase: Any, operator: OperatorContext, role: str, expires_in_days: int, now: datetime) -> InviteCreated:
    token = new_secret(INVITE_PREFIX)
    expires_at = now + timedelta(days=expires_in_days)
    data = await _rpc(
        supabase, "control_member_invite_create",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_role": role, "p_token_hash": sha256(token), "p_expires_at": expires_at.isoformat()},
        not_found_detail="Organization not found.", conflict_detail="The invite could not be created. Try again.",
    )
    if isinstance(data, dict) and data.get("limit"):
        raise _conflict("An organization can have at most 20 pending invites. Revoke one first.")
    res = await supabase.table("member_invites").select(INVITE_COLUMNS).eq("organization_id", str(operator.organization_id)).eq("id", str(data["id"])).execute()
    rows = list(res.data or [])
    if len(rows) != 1:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "The invite was created but could not be read back. Revoke it and try again.")
    get_metrics().increment_counter("onboarding_total", labels={"event": "invite_created"})
    return InviteCreated(token=token, join_path=f"/join?token={token}", invite=_invite_view(dict(rows[0]), now))


async def list_invites(supabase: Any, operator: OperatorContext, now: datetime) -> InviteList:
    res = await supabase.table("member_invites").select(INVITE_COLUMNS).eq("organization_id", str(operator.organization_id)).order("created_at", desc=True).execute()
    return InviteList(invites=[_invite_view(dict(r), now) for r in (res.data or [])][:100])


async def revoke_invite(supabase: Any, operator: OperatorContext, invite_id: UUID) -> InviteRevokeResponse:
    data = await _rpc(
        supabase, "control_member_invite_revoke",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_invite_id": str(invite_id)},
        not_found_detail="Invite not found.", conflict_detail="The invite could not be revoked. Try again.",
    )
    return InviteRevokeResponse(id=invite_id, changed=bool(data["changed"]))


async def list_members(supabase: Any, operator: OperatorContext) -> MemberList:
    res = await supabase.rpc("list_organization_members", {"p_org": str(operator.organization_id)}).execute()
    return MemberList(members=[
        MemberView(user_id=UUID(str(r["user_id"])), email=r.get("email"), role=r["role"], joined_at=_parse(r.get("joined_at"))) for r in (res.data or [])
    ])


async def set_role(supabase: Any, operator: OperatorContext, user_id: UUID, role: str, confirm: bool) -> SetRoleResponse:
    if role == "owner" and not confirm:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Making someone an owner requires explicit confirmation: send "confirm": true.')
    data = await _rpc(
        supabase, "control_member_set_role",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_user": str(user_id), "p_role": role},
        not_found_detail="Member not found.", conflict_detail="The last owner cannot be demoted. Make someone else an owner first.",
    )
    return SetRoleResponse(user_id=user_id, changed=bool(data["changed"]), role=role)  # type: ignore[arg-type]


async def remove_member(supabase: Any, operator: OperatorContext, user_id: UUID) -> RemoveMemberResponse:
    await _rpc(
        supabase, "control_member_remove",
        {"p_org": str(operator.organization_id), "p_actor": str(operator.user_id), "p_user": str(user_id)},
        not_found_detail="Member not found.", conflict_detail="The last owner cannot be removed. Make someone else an owner first.",
    )
    return RemoveMemberResponse(user_id=user_id, removed=True)


def can_manage(role: Role) -> bool:
    return role >= Role.ADMIN


async def whoami(supabase: Any, operator: OperatorContext) -> MeResponse:
    res = await supabase.table("organizations").select("name,slug,deletion_purge_after").eq("id", str(operator.organization_id)).limit(1).execute()
    rows = list(res.data or [])
    row = dict(rows[0]) if rows else {}
    return MeResponse(
        user_id=operator.user_id, email=operator.email, organization_id=operator.organization_id,
        organization_name=str(row.get("name") or ""), role=operator.role.name.lower(),  # type: ignore[arg-type]
        organization_slug=str(row.get("slug") or ""), deletion_purge_after=_parse(row.get("deletion_purge_after")),
    )
