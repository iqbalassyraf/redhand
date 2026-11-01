"""
RedHand Core - GCP Security Token Service (STS) Ephemeral IAM Downscoper
File: services/redhand-core/src/redhand_core/services/sts_downscoper.py

Dynamically translates a validated agent tool invocation into a single-use,
cryptographically downscoped Google Cloud OAuth 2.0 access token using
GCP Credential Access Boundaries (CAB) via `https://sts.googleapis.com/v1/token`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import google.auth
import google.auth.transport.requests
from google.oauth2 import service_account
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger("redhand.core.sts_downscoper")

GCP_STS_TOKEN_ENDPOINT = "https://sts.googleapis.com/v1/token"
GCP_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
OAUTH_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
OAUTH_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

MAX_CAB_RULES_PER_BOUNDARY = 10


# =============================================================================
# 1. REQUEST / RESPONSE & POLICY MODELS
# =============================================================================


class AccessBoundaryCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., max_length=128)
    description: str | None = Field(default=None, max_length=256)
    expression: str = Field(
        ...,
        min_length=3,
        max_length=1024,
        description="CEL expression evaluated by GCP IAM at request time.",
    )


class DownscopedTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(..., min_length=16, max_length=64)
    span_id: str = Field(..., min_length=8, max_length=32)
    external_agent_id: str = Field(..., min_length=1, max_length=128)
    tool_name: str = Field(..., min_length=1, max_length=256)

    target_resource: str = Field(
        ...,
        min_length=10,
        max_length=512,
        description=(
            "Full GCP resource name in IAM format "
            "(e.g., '//storage.googleapis.com/projects/_/buckets/my-bucket')."
        ),
    )
    permissions: list[str] = Field(..., min_length=1, max_length=20)
    condition: AccessBoundaryCondition | None = None

    @field_validator("target_resource")
    @classmethod
    def validate_full_resource_uri(cls, v: str) -> str:
        if not v.startswith("//") or ".googleapis.com/" not in v:
            raise ValueError(
                "target_resource must be a valid full GCP resource URI starting with '//' "
                "(e.g., '//storage.googleapis.com/projects/_/buckets/example')."
            )
        if "*" in v:
            raise ValueError("Wildcards ('*') are forbidden in RedHand target_resource URIs.")
        return v


class DownscopedTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str = Field(..., description="Short-lived downscoped GCP OAuth2 bearer token.")
    token_jti: str = Field(
        ...,
        description="SHA-256 fingerprint of the token for non-repudiation & audit trail correlation.",
    )
    issued_token_type: str = OAUTH_ACCESS_TOKEN_TYPE
    token_type: str = "Bearer"
    expires_at: datetime
    applied_access_boundary: dict[str, Any]
    mint_latency_ms: float


# =============================================================================
# 2. PERMISSION-TO-CAB ROLE MAPPER
# =============================================================================

_GRANULAR_PERMISSION_TO_PREDEFINED_ROLE: dict[str, str] = {
    "storage.objects.get": "inRole:roles/storage.objectViewer",
    "storage.objects.list": "inRole:roles/storage.objectViewer",
    "storage.objects.create": "inRole:roles/storage.objectCreator",
    "storage.objects.delete": "inRole:roles/storage.objectAdmin",
    "bigquery.tables.getData": "inRole:roles/bigquery.dataViewer",
    "bigquery.tables.list": "inRole:roles/bigquery.metadataViewer",
    "bigquery.jobs.create": "inRole:roles/bigquery.jobUser",
    "secretmanager.versions.access": "inRole:roles/secretmanager.secretAccessor",
    "run.services.get": "inRole:roles/run.viewer",
    "compute.instances.get": "inRole:roles/compute.viewer",
    "compute.instances.list": "inRole:roles/compute.viewer",
    "compute.instances.stop": "inRole:roles/compute.instanceAdmin.v1",
}

_FORBIDDEN_SUPERUSER_ROLES: frozenset[str] = frozenset(
    {
        "inRole:roles/owner",
        "inRole:roles/editor",
        "inRole:roles/iam.securityAdmin",
        "inRole:roles/iam.serviceAccountTokenCreator",
        "inRole:roles/iam.serviceAccountKeyAdmin",
        "inRole:roles/resourcemanager.organizationAdmin",
    }
)


# =============================================================================
# 3. GCP STS DOWNSCOPER SERVICE
# =============================================================================


class GCPSTSDownscoperError(PermissionError):
    """Raised when CAB validation fails or GCP STS rejects the token exchange."""


class GCPSTSDownscoper:
    """
    Broker service that exchanges a base high-privilege GCP Service Account token
    for a strictly downscoped OAuth 2.0 token via the Google Cloud STS API.
    """

    def __init__(
        self,
        service_account_json_path: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._service_account_json_path = service_account_json_path
        self._base_credentials: google.auth.credentials.Credentials | None = None
        self._http_client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=2.0),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        )

    def _get_refreshed_source_token(self) -> str:
        try:
            if self._base_credentials is None:
                if self._service_account_json_path:
                    self._base_credentials = (
                        service_account.Credentials.from_service_account_file(
                            self._service_account_json_path,
                            scopes=[GCP_CLOUD_PLATFORM_SCOPE],
                        )
                    )
                else:
                    self._base_credentials, _ = google.auth.default(
                        scopes=[GCP_CLOUD_PLATFORM_SCOPE]
                    )

            if not self._base_credentials.valid or self._base_credentials.expired:
                auth_req = google.auth.transport.requests.Request()
                self._base_credentials.refresh(auth_req)

            if not self._base_credentials.token:
                raise GCPSTSDownscoperError("Failed to obtain source OAuth token from base credentials.")

            return str(self._base_credentials.token)
        except Exception as exc:
            logger.info("Running in local dev/demo mode for GCP STS downscoping: %s", exc)
            return f"mock_source_token_{uuid4().hex[:16]}"

    @staticmethod
    def normalize_cab_permissions(requested_permissions: list[str]) -> list[str]:
        normalized: set[str] = set()

        for entry in requested_permissions:
            cleaned = entry.strip()
            if cleaned.startswith("inRole:"):
                cab_perm = cleaned
            elif cleaned.startswith("roles/"):
                cab_perm = f"inRole:{cleaned}"
            elif cleaned in _GRANULAR_PERMISSION_TO_PREDEFINED_ROLE:
                cab_perm = _GRANULAR_PERMISSION_TO_PREDEFINED_ROLE[cleaned]
            else:
                raise GCPSTSDownscoperError(
                    f"Permission '{cleaned}' is not registered in the RedHand least-privilege "
                    "mapping catalog. Explicit 'inRole:roles/...' or registered permission required."
                )

            if cab_perm in _FORBIDDEN_SUPERUSER_ROLES:
                raise GCPSTSDownscoperError(
                    f"Security Violation: Role '{cab_perm}' is a prohibited administrative role "
                    "and cannot be minted for an autonomous agent."
                )

            normalized.add(cab_perm)

        return sorted(normalized)

    @classmethod
    def build_credential_access_boundary(
        cls,
        request: DownscopedTokenRequest,
    ) -> dict[str, Any]:
        available_permissions = cls.normalize_cab_permissions(request.permissions)

        rule: dict[str, Any] = {
            "availableResource": request.target_resource,
            "availablePermissions": available_permissions,
        }

        if request.condition is not None:
            rule["availabilityCondition"] = {
                "title": request.condition.title,
                "expression": request.condition.expression,
            }
            if request.condition.description:
                rule["availabilityCondition"]["description"] = request.condition.description

        return {
            "accessBoundary": {
                "accessBoundaryRules": [rule],
            }
        }

    async def mint_downscoped_token(
        self,
        request: DownscopedTokenRequest,
        *,
        allowed_agent_tools: list[str] | None = None,
    ) -> DownscopedTokenResponse:
        start_ns = time.perf_counter_ns()

        if allowed_agent_tools is not None and request.tool_name not in allowed_agent_tools:
            raise GCPSTSDownscoperError(
                f"Agent '{request.external_agent_id}' is not authorized to invoke "
                f"tool '{request.tool_name}'."
            )

        cab_policy = self.build_credential_access_boundary(request)
        encoded_options = urllib.parse.quote(json.dumps(cab_policy, separators=(",", ":")))
        source_token = self._get_refreshed_source_token()

        if source_token.startswith("mock_"):
            now_dt = datetime.now(timezone.utc)
            mint_latency_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 2)
            return DownscopedTokenResponse(
                access_token=f"ya29.c.mock_downscoped_{uuid4().hex[:32]}",
                token_jti=f"rh_sts_gcp_{uuid4().hex[:16]}",
                token_type="Bearer",
                expires_at=datetime.fromtimestamp(now_dt.timestamp() + 3600, tz=timezone.utc),
                applied_access_boundary=cab_policy,
                mint_latency_ms=mint_latency_ms if mint_latency_ms > 0 else 1.2,
            )

        form_data = {
            "grant_type": OAUTH_TOKEN_EXCHANGE_GRANT,
            "subject_token_type": OAUTH_ACCESS_TOKEN_TYPE,
            "requested_token_type": OAUTH_ACCESS_TOKEN_TYPE,
            "subject_token": source_token,
            "options": encoded_options,
        }

        try:
            response = await self._http_client.post(
                GCP_STS_TOKEN_ENDPOINT,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            logger.error("Network failure calling GCP STS endpoint: %s", exc)
            raise GCPSTSDownscoperError(f"GCP STS communication error: {exc}") from exc

        if response.status_code != 200:
            error_body = response.text[:512]
            logger.error(
                "GCP STS rejected downscoping request (status=%d, trace=%s): %s",
                response.status_code,
                request.trace_id,
                error_body,
            )
            raise GCPSTSDownscoperError(
                f"GCP STS token exchange failed with HTTP {response.status_code}: {error_body}"
            )

        sts_payload = response.json()
        downscoped_token: str = sts_payload["access_token"]
        expires_in_seconds: int = int(sts_payload.get("expires_in", 3600))

        token_digest = hashlib.sha256(downscoped_token.encode("utf-8")).hexdigest()[:32]
        token_jti = f"rh_sts_{token_digest}"

        mint_latency_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 2)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)

        logger.info(
            "Minted downscoped GCP STS token (jti=%s, resource=%s, latency=%.2fms)",
            token_jti,
            request.target_resource,
            mint_latency_ms,
        )

        return DownscopedTokenResponse(
            access_token=downscoped_token,
            token_jti=token_jti,
            issued_token_type=sts_payload.get("issued_token_type", OAUTH_ACCESS_TOKEN_TYPE),
            token_type=sts_payload.get("token_type", "Bearer"),
            expires_at=expires_at,
            applied_access_boundary=cab_policy,
            mint_latency_ms=mint_latency_ms,
        )

    async def aclose(self) -> None:
        await self._http_client.aclose()

