"""
Verification of operator access tokens signed with asymmetric keys (Supabase "JWT Signing
Keys"), using the project's public JWKS.

Rules (docs/plans/operator-jwks-verification.md):
- Only ES256 (P-256) and RS256 (>= 2048 bits) are accepted. HS256, `none` and every other
  algorithm are rejected before any key is looked up, so a token cannot pick its own
  verification method (no algorithm-confusion attack).
- The key is chosen by the token's `kid`; the token's `alg` must match the key's type.
- `iss`, `aud`, `exp`, `sub` and `iat` are required and checked.
- Keys are cached for 10 minutes. An unknown `kid` or a stale cache triggers a refetch, at most
  one every 30 seconds. If refreshing fails, cached keys keep working for at most one hour in
  total, then everything is denied.
- Any failure (network, parsing, unusable keys) denies; nothing falls back to accepting tokens.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
import time
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, SECP256R1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import httpx
import jwt

logger = logging.getLogger("redhand.core.auth.jwks")

JWKS_ALGORITHMS = ("ES256", "RS256")
OPERATOR_JWT_AUDIENCE = "authenticated"
LEEWAY_SECONDS = 30
CACHE_SECONDS = 600.0
MIN_REFETCH_SECONDS = 30.0
MAX_STALE_SECONDS = 3600.0
MAX_JWKS_BYTES = 64 * 1024
MIN_RSA_BITS = 2048


class OperatorTokenError(Exception):
    """The operator token is invalid, or keys to verify it are unavailable. Always a 401."""


class JwksFetchError(Exception):
    """The JWKS could not be fetched or contained no usable key."""


@dataclass(frozen=True, slots=True)
class _VerificationKey:
    algorithm: str
    key: EllipticCurvePublicKey | RSAPublicKey


def _parse_key(jwk: dict[str, Any]) -> tuple[str, _VerificationKey] | None:
    """Returns (kid, key) for a usable signing key, else None."""
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid or jwk.get("use", "sig") != "sig":
        return None
    try:
        public = jwt.PyJWK(jwk).key
    except jwt.PyJWTError:
        return None
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "EC" and crv == "P-256" and isinstance(public, EllipticCurvePublicKey):
        if not isinstance(public.curve, SECP256R1):
            return None
        algorithm = "ES256"
    elif kty == "RSA" and isinstance(public, RSAPublicKey) and public.key_size >= MIN_RSA_BITS:
        algorithm = "RS256"
    else:
        return None
    declared = jwk.get("alg")
    if declared is not None and declared != algorithm:
        return None
    return kid, _VerificationKey(algorithm=algorithm, key=public)


class OperatorJwksVerifier:
    def __init__(
        self,
        *,
        jwks_url: str,
        issuer: str,
        http_client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        audience: str = OPERATOR_JWT_AUDIENCE,
        algorithms: tuple[str, ...] = JWKS_ALGORITHMS,
    ) -> None:
        # Clerk (ADR 0032) uses its own audience and RS256 only; any algorithm outside the allowlist is refused before a key is looked up.
        if not algorithms or any(a not in JWKS_ALGORITHMS for a in algorithms):
            raise ValueError("algorithms must be a non-empty subset of ES256 and RS256")
        self._audience = audience
        self._algorithms = algorithms
        self._url = jwks_url
        self._issuer = issuer
        self._http = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(3.0, connect=2.0), follow_redirects=False
        )
        self._clock = clock
        self._keys: dict[str, _VerificationKey] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None
        self._lock = asyncio.Lock()

    async def _fetch(self) -> dict[str, _VerificationKey]:
        try:
            response = await self._http.get(self._url)
            response.raise_for_status()
            if len(response.content) > MAX_JWKS_BYTES:
                raise JwksFetchError("JWKS response is too large.")
            document = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise JwksFetchError(type(exc).__name__) from exc
        raw_keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(raw_keys, list):
            raise JwksFetchError("JWKS document has no key list.")
        parsed = (_parse_key(k) for k in raw_keys if isinstance(k, dict))
        keys = dict(item for item in parsed if item is not None)
        if not keys:
            # Never replace a working cache with an empty or unusable key set.
            raise JwksFetchError("JWKS contains no usable signing key.")
        return keys

    async def _refresh_if_needed(self, kid: str) -> None:
        now = self._clock()
        fresh = self._fetched_at is not None and now - self._fetched_at < CACHE_SECONDS
        if fresh and kid in self._keys:
            return
        async with self._lock:
            now = self._clock()
            fresh = self._fetched_at is not None and now - self._fetched_at < CACHE_SECONDS
            if fresh and kid in self._keys:
                return
            if self._last_attempt is not None and now - self._last_attempt < MIN_REFETCH_SECONDS:
                return
            self._last_attempt = now
            try:
                self._keys = await self._fetch()
                self._fetched_at = self._clock()
            except JwksFetchError as exc:
                logger.error("Operator JWKS refresh failed: %s", exc)

    async def _key_for(self, kid: str) -> _VerificationKey:
        await self._refresh_if_needed(kid)
        key = self._keys.get(kid)
        if key is None or self._fetched_at is None:
            raise OperatorTokenError("No verification key for this token.")
        if self._clock() - self._fetched_at > MAX_STALE_SECONDS:
            logger.error("Operator JWKS has been unreachable for over an hour; denying tokens")
            raise OperatorTokenError("Verification keys are stale.")
        return key

    async def verify(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise OperatorTokenError("Malformed token.") from exc
        algorithm, kid = header.get("alg"), header.get("kid")
        if algorithm not in self._algorithms:
            raise OperatorTokenError("Unsupported token algorithm.")
        if not isinstance(kid, str) or not kid:
            raise OperatorTokenError("Token has no key id.")

        verification_key = await self._key_for(kid)
        if verification_key.algorithm != algorithm:
            raise OperatorTokenError("Token algorithm does not match its key.")
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                verification_key.key,
                algorithms=[verification_key.algorithm],
                audience=self._audience,
                issuer=self._issuer,
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            raise OperatorTokenError(type(exc).__name__) from exc
        return claims
