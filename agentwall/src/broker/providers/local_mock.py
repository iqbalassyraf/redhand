"""
Local Cryptographic Mock STS Provider (Zero-config HMAC-SHA256 JIT tokens).
"""

import base64
import hashlib
import hmac
import json
import time
from uuid import uuid4
from .base import BaseSTSProvider, EphemeralToken


class LocalMockSTSProvider(BaseSTSProvider):
    def __init__(self, signing_secret: str = "agentwall-ephemeral-hmac-key-v1") -> None:
        self._secret = signing_secret.encode("utf-8")

    async def mint_token(
        self,
        *,
        agent_id: str,
        tool_name: str,
        target_audience: str,
        ttl_seconds: int = 60,
    ) -> EphemeralToken:
        ttl = max(1, min(ttl_seconds, 60))  # strictly clamped <= 60s
        now = time.time()
        exp = now + ttl
        jti = f"aw_jit_{uuid4().hex[:16]}"

        claims = {
            "iss": "agentwall.internal/sts",
            "sub": agent_id,
            "aud": target_audience,
            "tool": tool_name,
            "iat": int(now),
            "exp": int(exp),
            "jti": jti,
        }

        payload_bytes = json.dumps(claims, sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
        signature = hmac.new(self._secret, payload_bytes, hashlib.sha256).hexdigest()[:32]
        token_str = f"aw_jit.{payload_b64}.{signature}"

        return EphemeralToken(
            access_token=token_str,
            token_type="Bearer",
            token_jti=jti,
            issued_at=now,
            expires_at=exp,
            ttl_seconds=ttl,
            target_audience=target_audience,
            bound_agent_id=agent_id,
            bound_tool_name=tool_name,
            provider_type="local_sts",
        )

    async def validate_token(self, token: EphemeralToken) -> bool:
        if token.is_expired():
            return False
        parts = token.access_token.split(".")
        if len(parts) != 3 or parts[0] != "aw_jit":
            return False
        try:
            padded_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload_bytes = base64.urlsafe_b64decode(padded_b64.encode("utf-8"))
            expected_sig = hmac.new(self._secret, payload_bytes, hashlib.sha256).hexdigest()[:32]
            return hmac.compare_digest(parts[2], expected_sig)
        except Exception:
            return False

