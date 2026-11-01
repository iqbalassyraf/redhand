"""
Development-only operator login.

Registered by `create_app` only when ENVIRONMENT is "development" AND the in-memory
local store is active, so it can never exist next to real customer data. It lets the
dashboard run without a Supabase project by issuing tokens for the seeded dev operators.
"""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from redhand_core.auth.operator import issue_operator_token
from redhand_core.config import Settings, get_settings
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS

router = APIRouter(prefix="/v1/dev", tags=["Development"])


class DevLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: Literal["owner", "admin", "operator", "operator2", "viewer"] = "owner"


class DevLoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    user_id: UUID
    email: str
    role: str
    organization_id: UUID


@router.post("/login", response_model=DevLoginResponse, summary="Development operator login")
async def dev_login(
    payload: DevLoginRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> DevLoginResponse:
    op = DEV_OPERATORS[payload.user]
    token = issue_operator_token(user_id=UUID(op["id"]), email=op["email"], settings=settings)
    return DevLoginResponse(
        access_token=token,
        user_id=UUID(op["id"]),
        email=op["email"],
        role=op["role"],
        organization_id=UUID(DEFAULT_ORG_ID),
    )
