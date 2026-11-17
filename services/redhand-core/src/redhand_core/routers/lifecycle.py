"""
Tenant data lifecycle (Phase 4.5 D1, ADR 0027). Owner only.
- GET  /v1/organization/export                   all of the organization's data as JSON (secrets left out; audited; one per hour)
- GET  /v1/organization/deletion                 whether deletion is pending and when the grace period ends
- POST /v1/organization/delete-request           start the 7-day grace period (the address name must be typed back; agents freeze, SDK keys switch off)
- POST /v1/organization/delete-request/cancel    end the grace period
While deletion is pending every other route answers 403 (see auth/operator.py); only these three and GET /v1/me stay open. The purge itself is not an API route:
only the database owner can run control_org_purge (docs/runbooks/tenant-data-deletion.md).
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response

from redhand_core.auth.operator import OwnerDep
from redhand_core.lifecycle import service
from redhand_core.lifecycle.models import DeleteRequest, DeletionRequested, DeletionStatus
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Tenant lifecycle"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get(
    "/v1/organization/export",
    response_class=Response,
    responses={
        200: {"content": {"application/json": {}}, "description": "The organization's data."}
    },
)
async def get_export(operator: OwnerDep, supabase: SupabaseDep) -> Response:
    body = await service.export_organization(supabase, operator)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="redhand-export.json"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/v1/organization/deletion", response_model=DeletionStatus)
async def get_deletion(operator: OwnerDep, supabase: SupabaseDep) -> DeletionStatus:
    return await service.deletion_status(supabase, operator)


@router.post("/v1/organization/delete-request", response_model=DeletionRequested)
async def post_delete_request(
    payload: DeleteRequest, operator: OwnerDep, supabase: SupabaseDep
) -> DeletionRequested:
    return await service.request_deletion(supabase, operator, payload.confirm_slug)


@router.post("/v1/organization/delete-request/cancel", response_model=DeletionStatus)
async def post_cancel_delete_request(operator: OwnerDep, supabase: SupabaseDep) -> DeletionStatus:
    return await service.cancel_deletion(supabase, operator)
