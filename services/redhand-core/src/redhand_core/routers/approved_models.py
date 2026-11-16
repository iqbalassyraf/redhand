"""
Approved models (Phase 4.5 B4b, ADR 0023): the organization's list of models its agents may use. Detective only.

- GET /v1/organization/approved-models  viewer: the list, its version, and whether the check is active (a non-empty list)
- PUT /v1/organization/approved-models  admin: replace the list (audited; clearing it needs "confirm"; a stale `version` is a 409)
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from redhand_core.approved import service
from redhand_core.approved.models import ApprovedModelsRequest, ApprovedModelsResponse
from redhand_core.auth.operator import AdminDep, ViewerDep
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Approved models"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/v1/organization/approved-models", response_model=ApprovedModelsResponse)
async def get_approved_models(operator: ViewerDep, supabase: SupabaseDep) -> ApprovedModelsResponse:
    return await service.get_list(supabase, operator.organization_id)


@router.put("/v1/organization/approved-models", response_model=ApprovedModelsResponse)
async def put_approved_models(payload: ApprovedModelsRequest, operator: AdminDep, supabase: SupabaseDep) -> ApprovedModelsResponse:
    return await service.set_list(supabase, operator, payload)
