"""
Organization SDK keys (Phase 4.5 C1a, ADR 0024). Keys let an agent's SDK send telemetry (traces, model use) for this organization.

- GET    /v1/organization/sdk-keys       any signed-in member: the keys (prefix, state, dates), never a secret or hash
- POST   /v1/organization/sdk-keys       admin: create one; the response holds the key ONCE (audited; at most 10 active; 1 to 365 days, default 90)
- DELETE /v1/organization/sdk-keys/{id}  admin: revoke (audited; idempotent)
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, status

from redhand_core.auth.operator import AdminDep, ViewerDep
from redhand_core.passports.models import utcnow
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.sdkkeys import service
from redhand_core.sdkkeys.models import SdkKeyCreated, SdkKeyCreateRequest, SdkKeyList, SdkKeyRevokeRequest, SdkKeyRevokeResponse

router = APIRouter(tags=["SDK keys"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/organization/sdk-keys", response_model=SdkKeyList)
async def get_sdk_keys(operator: ViewerDep, supabase: SupabaseDep) -> SdkKeyList:
    return await service.list_keys(supabase, operator.organization_id, utcnow())


@router.post("/v1/organization/sdk-keys", response_model=SdkKeyCreated, status_code=status.HTTP_201_CREATED)
async def post_sdk_key(payload: SdkKeyCreateRequest, operator: AdminDep, supabase: SupabaseDep) -> SdkKeyCreated:
    return await service.create_key(supabase, operator, payload, utcnow())


@router.delete("/v1/organization/sdk-keys/{key_id}", response_model=SdkKeyRevokeResponse)
async def delete_sdk_key(key_id: UUID, operator: AdminDep, supabase: SupabaseDep, payload: SdkKeyRevokeRequest | None = None) -> SdkKeyRevokeResponse:
    return await service.revoke_key(supabase, operator, key_id, payload.reason if payload else None)
