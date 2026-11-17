"""
Onboarding (Phase 4.5 D1, ADR 0026).

A signed-in person with no organization (UserDep: a verified token, no tenant):
- POST /v1/organizations              create one with a single-use sign-up code (SIGNUP_MODE "invite"); they become its owner
- POST /v1/invites/accept             join one with an invite token
Admins of an organization:
- GET/POST /v1/organization/invites, DELETE /v1/organization/invites/{id}     member invites (token shown once, 1 to 30 days)
- GET /v1/organization/members, PUT/DELETE /v1/organization/members/{user_id} members and roles (owner role needs confirmation; the last owner stays)
The platform owner (internal service token):
- POST /internal/v1/signup-codes      issue a sign-up code (scripts/issue_signup_code.py)
Both attempt routes are rate-limited per person and per source address, before any lookup, and answer the same way for every reason a code can fail.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status

from redhand_core.auth.operator import AdminDep, UserDep, ViewerDep
from redhand_core.config import Settings, get_settings
from redhand_core.net.source import client_source
from redhand_core.onboarding import service
from redhand_core.onboarding.models import (
    AcceptInviteRequest,
    AcceptInviteResponse,
    CreateOrganizationRequest,
    CreateOrganizationResponse,
    InviteCreated,
    InviteCreateRequest,
    InviteList,
    InviteRevokeResponse,
    MeResponse,
    MemberList,
    RemoveMemberResponse,
    SetRoleRequest,
    SetRoleResponse,
    SignupCodeCreated,
    SignupCodeRequest,
)
from redhand_core.passports.models import utcnow
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Onboarding"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def _limit(request: Request, user: UserDep, settings: Settings) -> None:
    service.check_rate(user.user_id, client_source(request.scope, settings.TRUSTED_PROXY_HOPS), settings.SIGNUPS_PER_HOUR_PER_USER, settings.SIGNUPS_PER_HOUR_PER_SOURCE)


@router.get("/v1/me", response_model=MeResponse)
async def get_me(operator: ViewerDep, supabase: SupabaseDep) -> MeResponse:
    return await service.whoami(supabase, operator)


@router.post("/v1/organizations", response_model=CreateOrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: CreateOrganizationRequest, request: Request, user: UserDep, supabase: SupabaseDep, settings: SettingsDep
) -> CreateOrganizationResponse:
    _limit(request, user, settings)
    return await service.create_organization(supabase, user, payload.name, payload.slug, payload.code, settings.SIGNUP_MODE)


@router.post("/v1/invites/accept", response_model=AcceptInviteResponse)
async def accept_invite(
    payload: AcceptInviteRequest, request: Request, user: UserDep, supabase: SupabaseDep, settings: SettingsDep
) -> AcceptInviteResponse:
    _limit(request, user, settings)
    return await service.accept_invite(supabase, user, payload.token)


@router.get("/v1/organization/invites", response_model=InviteList)
async def get_invites(operator: AdminDep, supabase: SupabaseDep) -> InviteList:
    return await service.list_invites(supabase, operator, utcnow())


@router.post("/v1/organization/invites", response_model=InviteCreated, status_code=status.HTTP_201_CREATED)
async def post_invite(payload: InviteCreateRequest, operator: AdminDep, supabase: SupabaseDep) -> InviteCreated:
    return await service.create_invite(supabase, operator, payload.role, payload.expires_in_days, utcnow())


@router.delete("/v1/organization/invites/{invite_id}", response_model=InviteRevokeResponse)
async def delete_invite(invite_id: UUID, operator: AdminDep, supabase: SupabaseDep) -> InviteRevokeResponse:
    return await service.revoke_invite(supabase, operator, invite_id)


@router.get("/v1/organization/members", response_model=MemberList)
async def get_members(operator: AdminDep, supabase: SupabaseDep) -> MemberList:
    return await service.list_members(supabase, operator)


@router.put("/v1/organization/members/{user_id}", response_model=SetRoleResponse)
async def put_member_role(user_id: UUID, payload: SetRoleRequest, operator: AdminDep, supabase: SupabaseDep) -> SetRoleResponse:
    return await service.set_role(supabase, operator, user_id, payload.role, payload.confirm)


@router.delete("/v1/organization/members/{user_id}", response_model=RemoveMemberResponse)
async def delete_member(user_id: UUID, operator: AdminDep, supabase: SupabaseDep) -> RemoveMemberResponse:
    return await service.remove_member(supabase, operator, user_id)


@router.post("/internal/v1/signup-codes", response_model=SignupCodeCreated, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_internal_service)])
async def issue_signup_code(payload: SignupCodeRequest, supabase: SupabaseDep) -> SignupCodeCreated:
    return await service.issue_signup_code(supabase, payload.note, payload.expires_in_days, utcnow())
