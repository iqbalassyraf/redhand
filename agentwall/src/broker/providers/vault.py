"""
HashiCorp Vault Dynamic Secret Lease Provider.
"""

import time
from typing import Any
from uuid import uuid4
from .base import BaseSTSProvider, EphemeralToken


class VaultSTSProvider(BaseSTSProvider):
    """
    HashiCorp Vault Dynamic Secret Lease Provider.
    Simulates dynamic credential leasing (e.g., Vault Database / Cloud secret engines).
    """

    def __init__(self, vault_addr: str = "http://127.0.0.1:8200") -> None:
        self.vault_addr = vault_addr

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
        lease_id = uuid4().hex
        jti = f"vault_lease_{lease_id[:16]}"
        access_token = f"hvs.CAES{lease_id.upper()}"

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
            provider_type="vault",
            user_id=user_id,
            user_roles=user_roles or [],
        )

    async def validate_token(self, token: EphemeralToken) -> bool:
        return not token.is_expired() and token.access_token.startswith("hvs.CAES")
