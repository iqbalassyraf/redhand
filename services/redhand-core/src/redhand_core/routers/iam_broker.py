"""
RedHand Core - Ephemeral IAM Minting Router (GCP + AWS)
File: services/redhand-core/src/redhand_core/routers/iam_broker.py
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from redhand_core.routers.telemetry import AuthenticatedOrgContext, verify_sdk_api_key
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

router = APIRouter(
    prefix="/v1/iam",
    tags=["Ephemeral IAM (Multi-Cloud STS Broker)"],
)

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
    _auth_ctx: Annotated[AuthenticatedOrgContext, Depends(verify_sdk_api_key)],
    downscoper: Annotated[GCPSTSDownscoper, Depends(get_sts_downscoper)],
) -> DownscopedTokenResponse:
    try:
        token = await downscoper.mint_downscoped_token(request)
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
    _auth_ctx: Annotated[AuthenticatedOrgContext, Depends(verify_sdk_api_key)],
    downscoper: Annotated[AWSSTSDownscoper, Depends(get_aws_downscoper)],
) -> AWSDownscopedTokenResponse:
    try:
        token = await downscoper.mint_downscoped_token(request)
        get_metrics().increment_counter("redhand_iam_tokens_minted_total", labels={"cloud": "aws"})
        return token
    except AWSSTSDownscoperError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
