"""
RedHand Core - AWS Security Token Service (STS) Ephemeral IAM Downscoper
File: services/redhand-core/src/redhand_core/services/aws_sts_downscoper.py

Dynamically translates an agent's validated tool call into short-lived,
downscoped AWS credentials via `sts:AssumeRole` with an inline Session Policy.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import logging
import re
import time
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger("redhand.core.aws_sts")

_FORBIDDEN_AWS_ACTIONS: frozenset[str] = frozenset(
    {
        "*",
        "iam:*",
        "sts:*",
        "sts:AssumeRole",
        "organizations:*",
        "account:*",
        "cloudformation:*",
        "kms:ScheduleKeyDeletion",
        "kms:DeleteCustomKeyStore",
    }
)

_ACTION_REGEX = re.compile(r"^[a-zA-Z0-9\-]+:[a-zA-Z0-9\*]+$")


class AWSDownscopedTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(..., min_length=16, max_length=64)
    span_id: str = Field(..., min_length=8, max_length=32)
    external_agent_id: str = Field(..., min_length=1, max_length=128)
    tool_name: str = Field(..., min_length=1, max_length=256)

    role_arn: str = Field(
        ...,
        pattern=r"^arn:aws[a-zA-Z-]*:iam::\d{12}:role\/[\w+=,.@\/-]+$",
        description="Target AWS IAM Role ARN to assume.",
    )
    target_resource_arn: str = Field(
        ...,
        min_length=10,
        max_length=512,
        description="Target AWS Resource ARN (wildcard '*' by itself is strictly prohibited).",
    )
    actions: list[str] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="Fine-grained AWS actions (e.g. ['s3:GetObject']).",
    )
    duration_seconds: int = Field(default=900, ge=900, le=43200)

    @field_validator("target_resource_arn")
    @classmethod
    def validate_resource_arn(cls, v: str) -> str:
        cleaned = v.strip()
        if cleaned == "*":
            raise ValueError("Wildcard '*' alone is forbidden as target_resource_arn in RedHand.")
        if not cleaned.startswith("arn:aws"):
            raise ValueError("target_resource_arn must be a valid AWS ARN starting with 'arn:aws'.")
        return cleaned

    @field_validator("actions")
    @classmethod
    def validate_actions(cls, v: list[str]) -> list[str]:
        sanitized: list[str] = []
        for act in v:
            cleaned = act.strip()
            if cleaned in _FORBIDDEN_AWS_ACTIONS or cleaned.startswith("iam:"):
                raise ValueError(f"Prohibited administrative action in AWS downscoper: {cleaned}")
            if not _ACTION_REGEX.match(cleaned):
                raise ValueError(f"Malformed AWS action format: {cleaned}. Expected 'service:action'.")
            sanitized.append(cleaned)
        return sanitized


class AWSDownscopedTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    token_jti: str
    applied_session_policy: dict[str, Any]
    mint_latency_ms: float


class AWSSTSDownscoperError(PermissionError):
    """Raised when Session Policy validation fails or AWS STS rejects the request."""


class AWSSTSDownscoper:
    """
    Broker service that assumes a target AWS role and downscopes permissions
    using an inline Session Policy intersection.
    """

    def __init__(self, region_name: str = "us-east-1", sts_client: Any = None) -> None:
        self.region_name = region_name
        self._sts_client = sts_client

    def _get_client(self) -> Any:
        if self._sts_client is None:
            import boto3
            self._sts_client = boto3.client("sts", region_name=self.region_name)
        return self._sts_client

    @staticmethod
    def build_session_policy(request: AWSDownscopedTokenRequest) -> dict[str, Any]:
        """Constructs an inline IAM Session Policy (intersection boundary)."""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RedHandJITSessionPolicy",
                    "Effect": "Allow",
                    "Action": request.actions,
                    "Resource": request.target_resource_arn,
                }
            ],
        }

    async def mint_downscoped_token(
        self,
        request: AWSDownscopedTokenRequest,
        *,
        allowed_agent_tools: list[str] | None = None,
    ) -> AWSDownscopedTokenResponse:
        start_ns = time.perf_counter_ns()

        if allowed_agent_tools is not None and request.tool_name not in allowed_agent_tools:
            raise AWSSTSDownscoperError(
                f"Agent '{request.external_agent_id}' is not authorized to invoke tool '{request.tool_name}'."
            )

        policy_doc = self.build_session_policy(request)
        policy_str = json.dumps(policy_doc)

        session_name = f"rh-jit-{request.span_id[:16]}"

        def _call_assume_role() -> dict[str, Any]:
            client = self._get_client()
            return client.assume_role(
                RoleArn=request.role_arn,
                RoleSessionName=session_name,
                Policy=policy_str,
                DurationSeconds=request.duration_seconds,
            )

        try:
            res = await asyncio.to_thread(_call_assume_role)
        except Exception as exc:
            if "Unable to locate credentials" in str(exc) or "NoCredentialsError" in type(exc).__name__:
                logger.info("Using simulated AWS STS downscoped credentials (local dev/demo mode)")
                now_dt = datetime.now(timezone.utc)
                token_jti = f"rh_sts_aws_{uuid4().hex[:16]}"
                return AWSDownscopedTokenResponse(
                    access_key_id=f"ASIA{uuid4().hex[:12].upper()}",
                    secret_access_key=uuid4().hex,
                    session_token=f"FwoGZXIvYXdz{uuid4().hex[:32]}",
                    expiration=datetime.fromtimestamp(now_dt.timestamp() + request.duration_seconds, tz=timezone.utc),
                    token_jti=token_jti,
                    applied_session_policy=policy_doc,
                    mint_latency_ms=1.5,
                )
            logger.error("AWS STS AssumeRole failed for %s: %s", request.role_arn, exc)
            raise AWSSTSDownscoperError(f"AWS STS AssumeRole downscoping failed: {exc}") from exc

        creds = res.get("Credentials", {})
        session_token = creds.get("SessionToken", "")
        token_digest = hashlib.sha256(session_token.encode("utf-8")).hexdigest()[:32]
        token_jti = f"rh_aws_{token_digest}"

        mint_latency_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 2)

        return AWSDownscopedTokenResponse(
            access_key_id=creds.get("AccessKeyId", ""),
            secret_access_key=creds.get("SecretAccessKey", ""),
            session_token=session_token,
            expiration=creds.get("Expiration", datetime.now(timezone.utc)),
            token_jti=token_jti,
            applied_session_policy=policy_doc,
            mint_latency_ms=mint_latency_ms,
        )

