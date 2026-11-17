"""
RedHand Core - Ephemeral IAM Minting Router (GCP + AWS)
File: services/redhand-core/src/redhand_core/routers/iam_broker.py
"""

from __future__ import annotations

import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from redhand_core.passports.models import effective_status, parse_scopes, utcnow
from redhand_core.routers.telemetry import AuthenticatedOrgContext, get_supabase_service_client, verify_sdk_api_key
from redhand_core.services.aws_sts_downscoper import (
    AWSDownscopedTokenRequest,
    AWSDownscopedTokenResponse,
    AWSSTSDownscoper,
    AWSSTSDownscoperError,
)
from redhand_core.services.metrics import get_metrics
from redhand_core.services.sts_downscoper import (
    DownscopedTokenRequest,
    DownscopedTokenResponse,
    GCPSTSDownscoper,
    GCPSTSDownscoperError,
)

logger = logging.getLogger(__name__)

NO_PASSPORT = "No active passport with this agent id exists in this organization, or it may not use this tool."

router = APIRouter(
    prefix="/v1/iam",
    tags=["Ephemeral IAM (Multi-Cloud STS Broker)"],
)

async def authorize_agent_for_tool(supabase: Any, organization_id: UUID, external_agent_id: str, tool_name: str) -> list[str] | None:
    """The tools the named agent may be given credentials for, or a refusal.

    An organization SDK key proves an organization, not an agent, so the request's agent id and tool are only claims. They are checked against the
    organization's own passport table: it must hold a passport with that id that is active (not frozen, revoked or expired) and not "reported only"
    (an agent first seen in telemetry has no gateway access until an admin promotes it). Returns None when a scope covers every tool (`*`), else the
    tools its scopes name (possibly none). Unknown, another organization's, and unusable agents all get the same refusal, so it is no oracle.
    A failed lookup refuses too (fail closed)."""
    try:
        res = await (
            supabase.table("agents").select("status, expires_at, scopes, reported_only")
            .eq("organization_id", str(organization_id)).eq("external_agent_id", external_agent_id).execute()
        )
    except Exception:  # noqa: BLE001 - any failure to read the passport must refuse, never allow
        logger.error("Broker passport lookup failed; refusing")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The passport could not be checked.") from None
    now = utcnow()
    for row in res.data or []:
        if row.get("reported_only") is True:
            continue
        try:
            if effective_status(str(row.get("status")), row.get("expires_at"), now) != "active":
                continue
            scopes = parse_scopes(row.get("scopes", []))
        except (KeyError, TypeError, ValueError):
            continue
        if any(scope.tool == "*" for scope in scopes):
            return None
        tools = [scope.tool for scope in scopes]
        if tool_name in tools:
            return tools
    raise HTTPException(status.HTTP_403_FORBIDDEN, NO_PASSPORT)


_gcp_downscoper_singleton: GCPSTSDownscoper | None = None
_aws_downscoper_singleton: AWSSTSDownscoper | None = None


def get_sts_downscoper() -> GCPSTSDownscoper:
    global _gcp_downscoper_singleton
    if _gcp_downscoper_singleton is None:
        _gcp_downscoper_singleton = GCPSTSDownscoper()
    return _gcp_downscoper_singleton


def get_aws_downscoper() -> AWSSTSDownscoper:
    global _aws_downscoper_singleton
    if _aws_downscoper_singleton is None:
        _aws_downscoper_singleton = AWSSTSDownscoper()
    return _aws_downscoper_singleton


@router.post(
    "/mint",
    response_model=DownscopedTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Mint a Single-Use Downscoped GCP OAuth2 Token via STS Credential Access Boundary",
)
@router.post(
    "/mint/gcp",
    response_model=DownscopedTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Mint a Single-Use Downscoped GCP OAuth2 Token via STS Credential Access Boundary",
)
async def mint_ephemeral_token_gcp(
    request: DownscopedTokenRequest,
    auth_ctx: Annotated[AuthenticatedOrgContext, Depends(verify_sdk_api_key)],
    downscoper: Annotated[GCPSTSDownscoper, Depends(get_sts_downscoper)],
    supabase: Annotated[Any, Depends(get_supabase_service_client)],
) -> DownscopedTokenResponse:
    allowed = await authorize_agent_for_tool(supabase, auth_ctx.organization_id, request.external_agent_id, request.tool_name)
    try:
        token = await downscoper.mint_downscoped_token(request, allowed_agent_tools=allowed)
        get_metrics().increment_counter("redhand_iam_tokens_minted_total", labels={"cloud": "gcp"})
        return token
    except GCPSTSDownscoperError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc


@router.post(
    "/mint/aws",
    response_model=AWSDownscopedTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Mint Single-Use Downscoped AWS Credentials via STS AssumeRole & Session Policy",
)
async def mint_ephemeral_token_aws(
    request: AWSDownscopedTokenRequest,
    auth_ctx: Annotated[AuthenticatedOrgContext, Depends(verify_sdk_api_key)],
    downscoper: Annotated[AWSSTSDownscoper, Depends(get_aws_downscoper)],
    supabase: Annotated[Any, Depends(get_supabase_service_client)],
) -> AWSDownscopedTokenResponse:
    allowed = await authorize_agent_for_tool(supabase, auth_ctx.organization_id, request.external_agent_id, request.tool_name)
    try:
        token = await downscoper.mint_downscoped_token(request, allowed_agent_tools=allowed)
        get_metrics().increment_counter("redhand_iam_tokens_minted_total", labels={"cloud": "aws"})
        return token
    except AWSSTSDownscoperError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
