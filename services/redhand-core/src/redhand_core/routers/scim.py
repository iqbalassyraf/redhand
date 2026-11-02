"""
RedHand Core - Enterprise SCIM v2.0 (RFC 7643 / RFC 7644) Directory Provisioning Router
File: services/redhand-core/src/redhand_core/routers/scim.py

Provides SCIM 2.0 endpoints for automated user & group provisioning from
Okta, Microsoft Entra ID (Azure AD), PingFederate, and Google Workspace.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hmac
import logging
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Header, Path, Query, status
from pydantic import BaseModel

from redhand_core.auth import bearer_token
from redhand_core.config import Settings, get_settings

logger = logging.getLogger("redhand.core.scim")

async def require_scim_token(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    settings: Settings = Depends(get_settings),
) -> None:
    """
    SCIM is an enterprise-tier feature. Every endpoint requires the configured bearer
    token; when none is configured the whole API is disabled (fail closed).
    NOTE: user/group storage below is an in-process, non-tenant-scoped demo store and
    must not be used for real directories until it is backed by the database.
    """
    expected = settings.SCIM_BEARER_TOKEN
    if expected is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="SCIM is not enabled.")
    presented = bearer_token(authorization)
    if not presented or not hmac.compare_digest(presented, expected.get_secret_value()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SCIM bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


router = APIRouter(
    prefix="/scim/v2",
    tags=["Enterprise SCIM 2.0 Directory Sync (RFC 7643/7644)"],
    dependencies=[Depends(require_scim_token)],
)

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"


# =============================================================================
# SCIM IN-MEMORY / ADAPTER STORE (For zero-config enterprise testing)
# =============================================================================

_SCIM_USERS: dict[str, dict[str, Any]] = {
    "00000000-0000-0000-0000-000000000001": {
        "id": "00000000-0000-0000-0000-000000000001",
        "userName": "alice.chen@enterprise.com",
        "displayName": "Alice Chen",
        "active": True,
        "emails": [{"value": "alice.chen@enterprise.com", "primary": True}],
        "roles": [{"value": "SecOps Lead"}],
        "groups": [{"value": "RedHand-SecOps-Approvers", "display": "RedHand SecOps Approvers"}],
        "meta": {
            "resourceType": "User",
            "created": "2026-10-30T00:00:00Z",
            "lastModified": "2026-10-31T00:00:00Z",
        },
    },
    "00000000-0000-0000-0000-000000000002": {
        "id": "00000000-0000-0000-0000-000000000002",
        "userName": "bob.vance@enterprise.com",
        "displayName": "Bob Vance",
        "active": True,
        "emails": [{"value": "bob.vance@enterprise.com", "primary": True}],
        "roles": [{"value": "Principal SRE"}],
        "groups": [{"value": "RedHand-SRE-Quorum", "display": "RedHand SRE Quorum"}],
        "meta": {
            "resourceType": "User",
            "created": "2026-10-30T00:00:00Z",
            "lastModified": "2026-10-31T00:00:00Z",
        },
    },
}


# =============================================================================
# SCIM WIRE MODELS
# =============================================================================


class SCIMName(BaseModel):
    formatted: str | None = None
    familyName: str | None = None
    givenName: str | None = None


class SCIMEmail(BaseModel):
    value: str
    type: str = "work"
    primary: bool = True


class SCIMUserCreateRequest(BaseModel):
    schemas: list[str] = [SCIM_USER_SCHEMA]
    userName: str
    displayName: str | None = None
    name: SCIMName | None = None
    emails: list[SCIMEmail] = []
    active: bool = True


# =============================================================================
# SCIM SERVICE PROVIDER CONFIG (Okta / Entra Discovery)
# =============================================================================


@router.get("/ServiceProviderConfig", summary="SCIM 2.0 Service Provider Configuration")
async def get_service_provider_config() -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://docs.redhand.security/enterprise/scim",
        "patch": {"supported": False},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 100},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "name": "OAuth Bearer Token",
                "description": "Authentication via Bearer SCIM API Key",
                "specUri": "http://www.rfc-editor.org/info/rfc6750",
                "type": "oauthbearertoken",
                "primary": True,
            }
        ],
    }


# =============================================================================
# SCIM USERS ENDPOINTS
# =============================================================================


@router.get("/Users", summary="Query Provisioned Users (RFC 7644)")
async def list_scim_users(
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=1, le=500),
    filter: str | None = Query(default=None),
) -> dict[str, Any]:
    users = list(_SCIM_USERS.values())
    if filter and "userName eq" in filter:
        target = filter.split("eq")[-1].strip().strip('"')
        users = [u for u in users if u.get("userName") == target]

    total = len(users)
    paginated = users[startIndex - 1 : startIndex - 1 + count]

    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": startIndex,
        "itemsPerPage": len(paginated),
        "Resources": paginated,
    }


@router.post(
    "/Users",
    status_code=status.HTTP_201_CREATED,
    summary="Provision a New Enterprise User via SCIM 2.0",
)
async def create_scim_user(payload: SCIMUserCreateRequest) -> dict[str, Any]:
    existing = next((u for u in _SCIM_USERS.values() if u["userName"] == payload.userName), None)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User '{payload.userName}' already exists.",
        )

    user_id = str(uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    disp_name = (
        payload.displayName
        or (payload.name.formatted if payload.name else None)
        or payload.userName
    )

    doc: dict[str, Any] = {
        "schemas": [SCIM_USER_SCHEMA],
        "id": user_id,
        "userName": payload.userName,
        "displayName": disp_name,
        "active": payload.active,
        "emails": [e.model_dump() for e in payload.emails],
        "roles": [{"value": "Security Operator"}],
        "groups": [{"value": "RedHand-Operators", "display": "RedHand Operators"}],
        "meta": {
            "resourceType": "User",
            "created": now_iso,
            "lastModified": now_iso,
        },
    }
    _SCIM_USERS[user_id] = doc
    logger.info("Provisioned new enterprise SCIM user: %s (id: %s)", payload.userName, user_id)
    return doc


@router.get("/Users/{user_id}", summary="Get Provisioned User by ID")
async def get_scim_user(user_id: Annotated[str, Path()]) -> dict[str, Any]:
    user = _SCIM_USERS.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SCIM User '{user_id}' not found.",
        )
    return user


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Deprovision User")
async def delete_scim_user(user_id: Annotated[str, Path()]) -> None:
    if user_id not in _SCIM_USERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SCIM User '{user_id}' not found.",
        )
    del _SCIM_USERS[user_id]
    logger.info("Deprovisioned SCIM user %s", user_id)


# =============================================================================
# SCIM GROUPS ENDPOINTS
# =============================================================================


@router.get("/Groups", summary="Query Enterprise RBAC Groups (RFC 7644)")
async def list_scim_groups() -> dict[str, Any]:
    groups = [
        {
            "schemas": [SCIM_GROUP_SCHEMA],
            "id": "grp-secops-approvers",
            "displayName": "RedHand-SecOps-Approvers",
            "members": [
                {"value": "00000000-0000-0000-0000-000000000001", "display": "Alice Chen"}
            ],
            "meta": {"resourceType": "Group"},
        },
        {
            "schemas": [SCIM_GROUP_SCHEMA],
            "id": "grp-sre-quorum",
            "displayName": "RedHand-SRE-Quorum",
            "members": [
                {"value": "00000000-0000-0000-0000-000000000002", "display": "Bob Vance"}
            ],
            "meta": {"resourceType": "Group"},
        },
    ]
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": len(groups),
        "startIndex": 1,
        "itemsPerPage": len(groups),
        "Resources": groups,
    }

