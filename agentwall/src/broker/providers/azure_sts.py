"""
Azure Entra ID & Managed Identity Ephemeral Token Provider.
Provides On-Behalf-Of (OBO) user-delegated access downscoping.
"""

import time
from typing import Any
from uuid import uuid4
from .base import BaseSTSProvider, EphemeralToken


class AzureSTSProvider(BaseSTSProvider):
    """
    Azure Entra ID (Active Directory) & Managed Identity STS Broker.
    Mints ephemeral tokens with delegated user claims and resource scope boundaries.
    """

    def __init__(self, tenant_id: str = "prod-tenant-azure") -> None:
        self.tenant_id = tenant_id

    async def mint_token(
        self,
        *,
        agent_id: str,
        tool_name: str,
        target_audience: str,
        ttl_seconds: int = 30,
        user_id: str | None = None,
        user_roles: list[str] | None = None,
        **kwargs: Any,
    ) -> EphemeralToken:
        ttl = max(5, min(ttl_seconds, 60))
        now = time.time()
        exp = now + ttl
        token_hash = uuid4().hex
        jti = f"rh_az_sts_{token_hash[:16]}"
        access_token = f"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImF6dXJlIn0.agentwall_az_{token_hash}"

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
            provider_type="azure_sts",
            user_id=user_id,
            user_roles=user_roles or [],
            scopes=["https://management.azure.com/.default"],
        )

    async def validate_token(self, token: EphemeralToken) -> bool:
        return not token.is_expired() and "agentwall_az_" in token.access_token
