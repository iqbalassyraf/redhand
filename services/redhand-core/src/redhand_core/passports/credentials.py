"""
Agent credentials.

- Agent key: a long-lived, high-entropy secret (`rh_agent_` + 256 random bits) given to
  the agent once. Only its SHA-256 hash is stored. SHA-256 (not a slow password hash)
  is appropriate because the key is random with 256 bits of entropy, so it cannot be
  brute-forced, and it keeps verification cheap.
- Access token: a short-lived (default 10 minutes) Ed25519-signed JWT that the agent
  presents to the gateway. The gateway holds only the public key, so it can verify but
  never mint tokens. Tokens carry the passport version so stale tokens are detectable.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import secrets
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt

AGENT_KEY_PREFIX = "rh_agent_"
AGENT_KEY_RANDOM_BYTES = 32
AGENT_KEY_DISPLAY_PREFIX_LENGTH = len(AGENT_KEY_PREFIX) + 6

AGENT_TOKEN_ISSUER = "redhand-core"
AGENT_TOKEN_AUDIENCE = "redhand-gateway"
AGENT_TOKEN_ALGORITHM = "EdDSA"


@dataclass(frozen=True, slots=True)
class NewAgentKey:
    plaintext: str
    key_hash: str
    display_prefix: str


def generate_agent_key() -> NewAgentKey:
    plaintext = AGENT_KEY_PREFIX + secrets.token_urlsafe(AGENT_KEY_RANDOM_BYTES)
    return NewAgentKey(
        plaintext=plaintext,
        key_hash=hash_agent_key(plaintext),
        display_prefix=plaintext[:AGENT_KEY_DISPLAY_PREFIX_LENGTH],
    )


def hash_agent_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def looks_like_agent_key(value: str) -> bool:
    """Cheap format check before any lookup; rejects junk without touching the database."""
    return (
        value.startswith(AGENT_KEY_PREFIX)
        and 40 <= len(value) <= 80
        and all(c.isalnum() or c in "_-" for c in value)
    )


class AgentTokenSigner:
    """Signs and describes agent access tokens with an Ed25519 key pair."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self._public_x = base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode("ascii")
        self.key_id = hashlib.sha256(public_raw).hexdigest()[:16]

    @classmethod
    def from_pem(cls, pem: str) -> AgentTokenSigner:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("AGENT_TOKEN_SIGNING_KEY must be an Ed25519 private key (PEM).")
        return cls(key)

    @classmethod
    def generate(cls) -> AgentTokenSigner:
        return cls(Ed25519PrivateKey.generate())

    def public_jwk(self) -> dict[str, str]:
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": self._public_x,
            "kid": self.key_id,
            "alg": AGENT_TOKEN_ALGORITHM,
            "use": "sig",
        }

    def public_pem(self) -> str:
        return (
            self._private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )

    def issue(
        self,
        *,
        agent_id: UUID,
        organization_id: UUID,
        passport_version: int,
        now: datetime,
        ttl: timedelta,
    ) -> tuple[str, str, datetime]:
        """Returns (token, jti, expires_at)."""
        jti = uuid4().hex
        expires_at = now + ttl
        claims: dict[str, Any] = {
            "iss": AGENT_TOKEN_ISSUER,
            "aud": AGENT_TOKEN_AUDIENCE,
            "sub": str(agent_id),
            "org": str(organization_id),
            "ver": passport_version,
            "jti": jti,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        token = jwt.encode(
            claims, self._private_key, algorithm=AGENT_TOKEN_ALGORITHM, headers={"kid": self.key_id}
        )
        return token, jti, expires_at
