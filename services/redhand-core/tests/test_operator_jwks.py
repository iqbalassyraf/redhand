"""
Operator tokens signed with asymmetric keys, verified through a JWKS
(docs/plans/operator-jwks-verification.md, ADR 0007).

A fake JWKS endpoint (httpx MockTransport) and generated keys stand in for Supabase.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import httpx
import jwt
from pydantic import SecretStr, ValidationError
import pytest

from redhand_core.auth import operator as operator_module
from redhand_core.auth.operator import issue_operator_token
from redhand_core.auth.operator_jwks import OperatorJwksVerifier, OperatorTokenError
from redhand_core.config import Settings
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS

from core_helpers import make_client, make_settings

ISSUER = "https://test-ref.supabase.co/auth/v1"
JWKS_URL = "https://test-ref.supabase.co/auth/v1/.well-known/jwks.json"

EC_1 = ec.generate_private_key(ec.SECP256R1())
EC_2 = ec.generate_private_key(ec.SECP256R1())
EC_OTHER = ec.generate_private_key(ec.SECP256R1())
EC_P384 = ec.generate_private_key(ec.SECP384R1())
RSA_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ec_jwk(private: ec.EllipticCurvePrivateKey, kid: str) -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": kid, "alg": "ES256", "use": "sig"})
    return jwk


def _rsa_jwk(private: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return jwk


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeJwks:
    """The Supabase JWKS endpoint."""

    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys
        self.requests = 0
        self.mode = "ok"

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.mode == "down":
            raise httpx.ConnectError("down", request=request)
        if self.mode == "500":
            return httpx.Response(500)
        if self.mode == "bad_json":
            return httpx.Response(200, content=b"not json")
        if self.mode == "huge":
            return httpx.Response(200, content=b"x" * (70 * 1024))
        if self.mode == "no_usable_key":
            return httpx.Response(200, json={"keys": [{"kty": "oct", "kid": "k1", "k": "AAAA"}]})
        return httpx.Response(200, json={"keys": self.keys})


def make_verifier(fake: FakeJwks, clock: FakeClock | None = None) -> OperatorJwksVerifier:
    return OperatorJwksVerifier(
        jwks_url=JWKS_URL,
        issuer=ISSUER,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
        clock=clock or FakeClock(),
    )


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "sub": DEV_OPERATORS["owner"]["id"],
        "aud": "authenticated",
        "iss": ISSUER,
        "iat": now,
        "exp": now + 600,
        "role": "authenticated",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def sign(
    key: Any = EC_1, *, kid: str | None = "k1", alg: str = "ES256", **overrides: Any
) -> str:
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(claims(**overrides), key, algorithm=alg, headers=headers)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def hs256_token(secret: bytes, kid: str = "k1") -> str:
    """Crafts an HS256 token by hand (PyJWT refuses to sign with a PEM public key)."""
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    payload = _b64(json.dumps(claims()).encode())
    signature = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(signature)}"


@pytest.fixture(autouse=True)
def _clear_verifier_cache() -> Any:
    operator_module._jwks_verifiers.clear()
    yield
    operator_module._jwks_verifiers.clear()


# ---------------------------------------------------------------------------
# Verifier: accepted tokens
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_es256_token_is_accepted() -> None:
    verifier = make_verifier(FakeJwks([_ec_jwk(EC_1, "k1")]))
    result = await verifier.verify(sign())
    assert result["sub"] == DEV_OPERATORS["owner"]["id"]


@pytest.mark.asyncio
async def test_valid_rs256_token_is_accepted() -> None:
    verifier = make_verifier(FakeJwks([_rsa_jwk(RSA_1, "r1")]))
    assert (await verifier.verify(sign(RSA_1, kid="r1", alg="RS256")))["aud"] == "authenticated"


@pytest.mark.asyncio
async def test_key_rotation_is_picked_up_after_the_refetch_interval() -> None:
    fake, clock = FakeJwks([_ec_jwk(EC_1, "k1")]), FakeClock()
    verifier = make_verifier(fake, clock)
    await verifier.verify(sign())
    assert fake.requests == 1

    fake.keys = [_ec_jwk(EC_1, "k1"), _ec_jwk(EC_2, "k2")]  # Supabase rotates
    with pytest.raises(OperatorTokenError):  # too soon to refetch: protects the endpoint
        await verifier.verify(sign(EC_2, kid="k2"))
    assert fake.requests == 1

    clock.now += 31
    assert (await verifier.verify(sign(EC_2, kid="k2")))["sub"]
    assert fake.requests == 2
    assert (await verifier.verify(sign()))["sub"]  # the old key still works while published


# ---------------------------------------------------------------------------
# Verifier: denied tokens
# ---------------------------------------------------------------------------


def _denied_tokens() -> dict[str, str]:
    now = int(time.time())
    return {
        "wrong-signature": sign(EC_OTHER, kid="k1"),
        "wrong-issuer": sign(iss="https://evil.example/auth/v1"),
        "wrong-audience": sign(aud="anon"),
        "expired": sign(exp=now - 300, iat=now - 900),
        "no-exp": sign(exp=None),
        "no-iss": sign(iss=None),
        "no-sub": sign(sub=None),
        "no-iat": sign(iat=None),
        "no-kid": sign(kid=None),
        "unknown-kid": sign(kid="does-not-exist"),
        "malformed": "not-a-jwt",
        "alg-mismatch-with-key": sign(RSA_1, kid="k1", alg="RS256"),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("name", list(_denied_tokens()))
async def test_invalid_tokens_are_denied(name: str) -> None:
    verifier = make_verifier(FakeJwks([_ec_jwk(EC_1, "k1")]))
    with pytest.raises(OperatorTokenError):
        await verifier.verify(_denied_tokens()[name])


@pytest.mark.asyncio
async def test_disallowed_algorithms_are_rejected_before_any_key_lookup() -> None:
    public_pem = EC_1.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    attacks = {
        "alg-none": jwt.encode(claims(), key="", algorithm="none", headers={"kid": "k1"}),
        "hs256-random-secret": hs256_token(b"a-random-secret-of-sufficient-length-0123456789"),
        # Classic algorithm confusion: HMAC with the PUBLIC key as the secret.
        "hs256-public-key-as-secret": hs256_token(public_pem),
        "es384": sign(EC_P384, alg="ES384"),
    }
    for name, token in attacks.items():
        fake = FakeJwks([_ec_jwk(EC_1, "k1")])
        with pytest.raises(OperatorTokenError):
            await make_verifier(fake).verify(token)
        assert fake.requests == 0, name


@pytest.mark.asyncio
async def test_unknown_kid_does_not_hammer_the_jwks_endpoint() -> None:
    fake = FakeJwks([_ec_jwk(EC_1, "k1")])
    verifier = make_verifier(fake)
    for _ in range(10):
        with pytest.raises(OperatorTokenError):
            await verifier.verify(sign(kid="nope"))
    assert fake.requests == 1


@pytest.mark.asyncio
async def test_keys_that_are_not_usable_signing_keys_are_ignored() -> None:
    weak = _ec_jwk(EC_1, "k1")
    wrong_use = {**_ec_jwk(EC_2, "k2"), "use": "enc"}
    mislabeled = {**_ec_jwk(EC_OTHER, "k3"), "alg": "RS256"}  # declared alg contradicts the key
    verifier = make_verifier(FakeJwks([weak, wrong_use, mislabeled]))
    await verifier.verify(sign())
    for key, kid in ((EC_2, "k2"), (EC_OTHER, "k3")):
        with pytest.raises(OperatorTokenError):
            await verifier.verify(sign(key, kid=kid))


# ---------------------------------------------------------------------------
# Verifier: failure modes (fail closed, bounded staleness)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jwks_down_on_cold_start_denies_then_recovers() -> None:
    fake, clock = FakeJwks([_ec_jwk(EC_1, "k1")]), FakeClock()
    fake.mode = "down"
    verifier = make_verifier(fake, clock)
    with pytest.raises(OperatorTokenError):
        await verifier.verify(sign())
    with pytest.raises(OperatorTokenError):
        await verifier.verify(sign())
    assert fake.requests == 1  # the second attempt did not refetch

    fake.mode, clock.now = "ok", clock.now + 31
    assert (await verifier.verify(sign()))["sub"]
    assert fake.requests == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["down", "500", "bad_json", "huge", "no_usable_key"])
async def test_bad_jwks_responses_never_authenticate_anything(mode: str) -> None:
    fake = FakeJwks([_ec_jwk(EC_1, "k1")])
    fake.mode = mode
    with pytest.raises(OperatorTokenError):
        await make_verifier(fake).verify(sign())


@pytest.mark.asyncio
async def test_cached_keys_survive_a_short_outage_but_not_an_hour() -> None:
    fake, clock = FakeJwks([_ec_jwk(EC_1, "k1")]), FakeClock()
    verifier = make_verifier(fake, clock)
    await verifier.verify(sign())

    fake.mode = "down"
    clock.now += 601  # cache is stale, refresh fails, cached key is still within the hour
    assert (await verifier.verify(sign()))["sub"]

    clock.now += 3000  # 3601 s after the last successful fetch: past the one-hour limit (literal on purpose)
    with pytest.raises(OperatorTokenError):
        await verifier.verify(sign())


@pytest.mark.asyncio
async def test_a_bad_refresh_does_not_replace_a_working_key_set() -> None:
    fake, clock = FakeJwks([_ec_jwk(EC_1, "k1")]), FakeClock()
    verifier = make_verifier(fake, clock)
    await verifier.verify(sign())
    fake.mode = "no_usable_key"
    clock.now += 601
    assert (await verifier.verify(sign()))["sub"]


# ---------------------------------------------------------------------------
# Configuration rules
# ---------------------------------------------------------------------------


def test_jwks_mode_requires_issuer_and_https_outside_development() -> None:
    with pytest.raises(ValidationError, match="OPERATOR_JWT_ISSUER"):
        Settings(ENVIRONMENT="staging", OPERATOR_JWKS_URL=JWKS_URL)
    with pytest.raises(ValidationError, match="https"):
        Settings(
            ENVIRONMENT="staging", OPERATOR_JWKS_URL="http://x.example/jwks.json", OPERATOR_JWT_ISSUER=ISSUER
        )
    ok = Settings(ENVIRONMENT="staging", OPERATOR_JWKS_URL=JWKS_URL, OPERATOR_JWT_ISSUER=ISSUER)
    assert ok.OPERATOR_JWT_SECRET is None  # JWKS mode never carries a shared secret


def test_both_modes_together_are_refused_outside_development() -> None:
    with pytest.raises(ValidationError, match="not both"):
        Settings(
            ENVIRONMENT="production",
            OPERATOR_JWKS_URL=JWKS_URL,
            OPERATOR_JWT_ISSUER=ISSUER,
            OPERATOR_JWT_SECRET=SecretStr("s" * 40),
        )


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_hs256_shared_secret_mode_is_refused_outside_development_and_test(environment: str) -> None:
    """Changed in H3.4 (was: "still works in staging"). A shared secret both verifies and mints operator tokens, so anyone holding it can sign
    in as any operator in any organization; shared environments use asymmetric keys (JWKS)."""
    with pytest.raises(ValidationError, match="only allowed when ENVIRONMENT is 'development' or 'test'"):
        Settings(ENVIRONMENT=environment, OPERATOR_JWT_SECRET=SecretStr("s" * 40))


@pytest.mark.parametrize("environment", ["development", "test"])
def test_hs256_shared_secret_mode_still_works_for_local_development_and_tests(environment: str) -> None:
    assert Settings(ENVIRONMENT=environment, OPERATOR_JWT_SECRET=SecretStr("s" * 40)).OPERATOR_JWKS_URL is None


# ---------------------------------------------------------------------------
# Through the HTTP API
# ---------------------------------------------------------------------------


def _jwks_client(fake: FakeJwks) -> Any:
    client, settings = make_client(
        OPERATOR_JWKS_URL=JWKS_URL, OPERATOR_JWT_ISSUER=ISSUER, OPERATOR_JWT_SECRET=None
    )
    assert settings.OPERATOR_JWT_SECRET is None
    operator_module._jwks_verifiers[(JWKS_URL, ISSUER)] = make_verifier(fake)
    return client


def test_supabase_style_token_authenticates_and_tenant_comes_from_membership() -> None:
    client = _jwks_client(FakeJwks([_ec_jwk(EC_1, "k1")]))
    resp = client.get("/v1/state/snapshot", headers={"Authorization": f"Bearer {sign()}"})
    assert resp.status_code == 200
    assert resp.json()["organization_id"] == DEFAULT_ORG_ID


def test_valid_token_for_a_user_without_membership_is_forbidden() -> None:
    client = _jwks_client(FakeJwks([_ec_jwk(EC_1, "k1")]))
    resp = client.get(
        "/v1/state/snapshot", headers={"Authorization": f"Bearer {sign(sub=str(uuid4()))}"}
    )
    assert resp.status_code == 403


def test_hs256_tokens_are_rejected_in_jwks_mode() -> None:
    client = _jwks_client(FakeJwks([_ec_jwk(EC_1, "k1")]))
    shared_secret_settings = make_settings()
    token = issue_operator_token(
        user_id=DEV_OPERATORS["owner"]["id"], email=None, settings=shared_secret_settings  # type: ignore[arg-type]
    )
    assert client.get("/v1/state/snapshot", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_http_requests_are_denied_while_the_jwks_is_unreachable() -> None:
    fake = FakeJwks([_ec_jwk(EC_1, "k1")])
    fake.mode = "down"
    client = _jwks_client(fake)
    resp = client.get("/v1/state/snapshot", headers={"Authorization": f"Bearer {sign()}"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid or expired operator token."  # no internals leaked


def test_dev_login_is_not_available_in_jwks_mode() -> None:
    from fastapi.testclient import TestClient

    from redhand_core.main import create_app

    settings = make_settings(
        ENVIRONMENT="development", OPERATOR_JWKS_URL=JWKS_URL, OPERATOR_JWT_ISSUER=ISSUER
    )
    resp = TestClient(create_app(settings)).post("/v1/dev/login", json={"user": "owner"})
    assert resp.status_code == 404
