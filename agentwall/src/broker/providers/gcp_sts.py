"""
Google Cloud Security Token Service (STS) Ephemeral Provider.
"""

import time
from typing import Any
from uuid import uuid4
from .base import BaseSTSProvider, EphemeralToken


class GCPSTSProvider(BaseSTSProvider):
    """
    GCP STS Provider simulating/integrating with Google Cloud Security Token Service
    with Credential Access Boundary (CAB) downscoping.
    """

    def __init__(self, project_id: str = "prod-agent-project") -> None:
        self.project_id = project_id

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
        ttl = max(1, min(ttl_seconds, 60))
        now = time.time()
        exp = now + ttl
        token_hash = uuid4().hex
        jti = f"rh_gcp_sts_{token_hash[:16]}"
        access_token = f"ya29.c.agentwall_cab_{token_hash}"

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
            provider_type="gcp_sts",
            user_id=user_id,
            user_roles=user_roles or [],
        )

    async def validate_token(self, token: EphemeralToken) -> bool:
        return not token.is_expired() and token.access_token.startswith("ya29.c.agentwall_")
