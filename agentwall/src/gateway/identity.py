"""
Agent identity at the gateway: verification of short-lived agent access tokens.

Tokens are Ed25519-signed JWTs issued by redhand-core. The gateway holds only public
keys, so it can verify tokens but never mint them. The verification key comes from
configuration (preferred) or from core's public JWKS endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any
from uuid import UUID

import httpx
import jwt
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = structlog.get_logger(__name__)

AGENT_TOKEN_ISSUER = "redhand-core"
AGENT_TOKEN_AUDIENCE = "redhand-gateway"
AGENT_TOKEN_ALGORITHMS = ["EdDSA"]
CLOCK_SKEW_LEEWAY_SECONDS = 30
JWKS_REFRESH_SECONDS = 600
JWKS_MIN_REFETCH_SECONDS = 30


class AgentAuthError(Exception):
    """The presented credential is missing, malformed, expired or not trusted."""


class KeyUnavailableError(Exception):
    """No verification key could be obtained (configuration or core unreachable)."""


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    agent_id: UUID
    organization_id: UUID
    passport_version: int
    token_id: str
    expires_at: int


class AgentTokenVerifier:
    def __init__(
        self,
        *,
        public_key_pem: str | None,
        jwks_url: str | None,
        http_client: httpx.AsyncClient | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        self._static_key: Ed25519PublicKey | None = None
        if public_key_pem:
            loaded = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            if not isinstance(loaded, Ed25519PublicKey):
                raise ValueError("AGENT_TOKEN_PUBLIC_KEY must be an Ed25519 public key (PEM).")
            self._static_key = loaded
        self._jwks_url = jwks_url
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(3.0, connect=2.0))
        self._clock = clock
        self._jwks: dict[str, Any] = {}
        self._jwks_fetched_at: float | None = None
        self._metrics: Any = None

    def attach_metrics(self, metrics: Any) -> None:
        """Lets the gateway time key refreshes. Optional: without it nothing is timed."""
        self._metrics = metrics

    async def _refresh_jwks(self) -> None:
        if not self._jwks_url:
            raise KeyUnavailableError("No agent token verification key is configured.")
        timer = time.perf_counter()
        try:
            resp = await self._http.get(self._jwks_url)
            resp.raise_for_status()
            keys = resp.json().get("keys", [])
            parsed = {k["kid"]: jwt.PyJWK(k).key for k in keys if k.get("kty") == "OKP" and "kid" in k}
        except (httpx.HTTPError, ValueError, KeyError, jwt.PyJWTError) as exc:
            logger.error("Failed to fetch agent token JWKS", error_type=type(exc).__name__)
            raise KeyUnavailableError("Agent token keys are unavailable.") from exc
        self._jwks = parsed
        self._jwks_fetched_at = self._clock()
        if self._metrics is not None:
            self._metrics.record_stage("jwks_refresh", (time.perf_counter() - timer) * 1000)

    async def _key_for(self, kid: str | None) -> Any:
        if self._static_key is not None:
            return self._static_key
        now = self._clock()
        stale = self._jwks_fetched_at is None or now - self._jwks_fetched_at > JWKS_REFRESH_SECONDS
        unknown_kid = kid is not None and kid not in self._jwks
        may_refetch = self._jwks_fetched_at is None or now - self._jwks_fetched_at > JWKS_MIN_REFETCH_SECONDS
        if stale or (unknown_kid and may_refetch):
            await self._refresh_jwks()
        if kid is None or kid not in self._jwks:
            raise AgentAuthError("Unknown token signing key.")
        return self._jwks[kid]

    async def verify(self, token: str) -> AgentIdentity:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AgentAuthError("Malformed token.") from exc
        if header.get("alg") not in AGENT_TOKEN_ALGORITHMS:
            raise AgentAuthError("Unsupported token algorithm.")

        key = await self._key_for(header.get("kid"))
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=AGENT_TOKEN_ALGORITHMS,
                audience=AGENT_TOKEN_AUDIENCE,
                issuer=AGENT_TOKEN_ISSUER,
                leeway=CLOCK_SKEW_LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "sub", "aud", "iss", "jti"]},
            )
            return AgentIdentity(
                agent_id=UUID(str(claims["sub"])),
                organization_id=UUID(str(claims["org"])),
                passport_version=int(claims["ver"]),
                token_id=str(claims["jti"]),
                expires_at=int(claims["exp"]),
            )
        except jwt.PyJWTError as exc:
            raise AgentAuthError(f"Invalid token: {type(exc).__name__}.") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentAuthError("Token is missing required RedHand claims.") from exc
