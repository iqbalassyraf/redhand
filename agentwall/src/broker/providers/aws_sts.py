"""
AWS Security Token Service (STS) Ephemeral Provider.
Simulates and orchestrates AWS STS AssumeRole / GetSessionToken with inline session policies.
"""

import time
from typing import Any
from uuid import uuid4
from .base import BaseSTSProvider, EphemeralToken


class AWSSTSProvider(BaseSTSProvider):
    """
    AWS STS Provider minting downscoped session credentials (ASIA...)
    strictly bound to target audience and tool scope boundaries.
    """

    def __init__(self, account_id: str = "123456789012", role_name: str = "AgentWallRestrictedRole") -> None:
        self.account_id = account_id
        self.role_name = role_name

    async def mint_token(
        self,
        *,
        agent_id: str,
        tool_name: str,
        target_audience: str,
        ttl_seconds: int = 60,
        user_id: str | None = None,
        user_roles: list[str] | None = None,
        **kwargs: Any,
    ) -> EphemeralToken:
        ttl = max(5, min(ttl_seconds, 60))
        now = time.time()
        exp = now + ttl
        token_hash = uuid4().hex
        jti = f"rh_aws_sts_{token_hash[:16]}"

        # AWS STS Session token format (ASIA...)
        access_token = f"ASIA{token_hash[:12].upper()}SESSION{token_hash[12:]}"

        return EphemeralToken(
            access_token=access_token,
            token_type="Bearer",
            token_jti=jti,
            issued_at=now,
            expires_at=exp,
            ttl_seconds=ttl,
            target_audience=target_audience,
            bound_agent_id=agent_id,
            bound_tool_name=tool_name,
            provider_type="aws_sts",
            user_id=user_id,
            user_roles=user_roles or [],
            scopes=[f"arn:aws:iam::{self.account_id}:role/{self.role_name}"],
        )

    async def validate_token(self, token: EphemeralToken) -> bool:
        return not token.is_expired() and token.access_token.startswith("ASIA")

