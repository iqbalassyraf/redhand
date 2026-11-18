"""
The gateway's route sweep (release-readiness 3.2, CLAUDE.md 5.3): the gateway is the control point, so every route either needs a credential that is checked
before anything happens, or is on a short allowlist with the reason. Built from the live route table: a route added later is covered, or this test fails.
  - operational routes (/metrics, /v1/policies) need the service token, and are closed when none is configured;
  - /mcp/{server} needs an agent access token: missing, malformed, someone else's kind of token, signed by another key, expired, wrong audience: all refused;
  - the public routes are health and static manifest vetting (size- and rate-limited, covered in its own tests).
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import jwt
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import SecretStr

from agentwall.src import main as gateway_main
from agentwall.src.main import app, require_service_token

SERVICE_TOKEN = "sweep-gateway-service-token-0123456789abcdef"

PUBLIC = {
    ("GET", "/health"): "liveness",
    ("GET", "/healthz"): "liveness",
    ("POST", "/v1/mcp/vet"): "static manifest vetting for the dashboard: size-limited (256 KiB) and rate-limited per caller, executes and fetches nothing",
}
AGENT_TOKEN_ROUTES = {("GET", "/mcp/{server}"), ("POST", "/mcp/{server}")}
SERVICE_ROUTES = {
    ("GET", "/metrics"), ("GET", "/v1/policies"),
    ("POST", "/internal/v1/radar/self-test"), ("POST", "/internal/v1/scan"),  # called by core with the service token; not in the public OpenAPI file
}


def routes() -> Iterator[tuple[str, str, Any]]:
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                yield method, route.path, route.dependant
        elif hasattr(route, "effective_route_contexts"):
            for ctx in route.effective_route_contexts():
                for method in sorted(set(ctx.methods) - {"HEAD", "OPTIONS"}):
                    yield method, ctx.path, ctx.dependant


def calls_in(dependant: Any) -> list[Any]:
    found: list[Any] = []
    for sub in dependant.dependencies:
        if sub.call is not None:
            found.append(sub.call)
        found.extend(calls_in(sub))
    return found


TABLE = {(m, p): d for m, p, d in routes()}


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(gateway_main.settings, "CORE_SERVICE_TOKEN", SecretStr(SERVICE_TOKEN))
    return TestClient(app)


def test_every_gateway_route_is_classified_and_nothing_is_unaccounted_for() -> None:
    declared = set(TABLE)
    assert declared == set(PUBLIC) | AGENT_TOKEN_ROUTES | SERVICE_ROUTES, f"gateway routes changed: {sorted(declared ^ (set(PUBLIC) | AGENT_TOKEN_ROUTES | SERVICE_ROUTES))}"
    for key in SERVICE_ROUTES:
        assert require_service_token in calls_in(TABLE[key]), f"{key} lost its service-token check"
    for key in set(PUBLIC) | AGENT_TOKEN_ROUTES:
        assert require_service_token not in calls_in(TABLE[key])


@pytest.mark.parametrize("method,path", sorted(SERVICE_ROUTES))
def test_operational_routes_refuse_a_missing_wrong_or_other_kind_of_token(client: TestClient, method: str, path: str) -> None:
    for label, headers in {
        "none": {},
        "wrong": {"Authorization": "Bearer nope"},
        "almost": {"Authorization": f"Bearer {SERVICE_TOKEN[:-1]}"},
        "not bearer": {"Authorization": f"Basic {SERVICE_TOKEN}"},
        "two tokens": {"Authorization": f"Bearer {SERVICE_TOKEN} extra"},
        "an agent-looking jwt": {"Authorization": "Bearer " + jwt.encode({"sub": "x"}, "k" * 40, algorithm="HS256")},
    }.items():
        response = client.request(method, path, headers=headers)
        assert response.status_code == 401, f"{method} {path} answered {response.status_code} to: {label}"
    assert client.request(method, path, headers={"Authorization": f"Bearer {SERVICE_TOKEN}"}).status_code != 401


@pytest.mark.parametrize("method,path", sorted(SERVICE_ROUTES))
def test_operational_routes_are_closed_when_no_service_token_is_configured(monkeypatch: pytest.MonkeyPatch, method: str, path: str) -> None:
    monkeypatch.setattr(gateway_main.settings, "CORE_SERVICE_TOKEN", None)
    response = TestClient(app).request(method, path, headers={"Authorization": f"Bearer {SERVICE_TOKEN}"})
    assert response.status_code == 401


def forged(**claims: Any) -> str:
    now = int(time.time())
    base = {"sub": "00000000-0000-0000-0000-000000000001", "iat": now, "exp": now + 300}
    return jwt.encode({**base, **claims}, "attacker-key-" + "x" * 32, algorithm="HS256")


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_the_tool_route_refuses_everything_that_is_not_a_valid_agent_token(client: TestClient, method: str) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    attempts: dict[str, dict[str, str]] = {
        "no header": {},
        "not bearer": {"Authorization": "Basic abc"},
        "garbage": {"Authorization": "Bearer not.a.jwt"},
        "the service token": {"Authorization": f"Bearer {SERVICE_TOKEN}"},
        "signed with another key": {"Authorization": "Bearer " + forged()},
        "expired": {"Authorization": "Bearer " + forged(iat=1, exp=2)},
        "alg none": {"Authorization": "Bearer " + jwt.encode({"sub": "x", "exp": int(time.time()) + 300}, None, algorithm="none")},
        "an operator-style token": {"Authorization": "Bearer " + forged(aud="redhand-operator", role="authenticated")},
    }
    for label, headers in attempts.items():
        response = client.request(method, "/mcp/xero", headers=headers, json=body if method == "POST" else None)
        # GET is not part of this gateway's MCP transport (405 before any credential is looked at); it must never be a 2xx.
        allowed = (401, 403) if method == "POST" else (401, 403, 405)
        assert response.status_code in allowed, f"{method} /mcp/xero answered {response.status_code} to: {label}"


def test_a_server_name_cannot_smuggle_a_path(client: TestClient) -> None:
    for slug in ("..%2Fadmin", "xero%2F..%2F..", "XERO", "a" * 80, "x y"):
        response = client.post(f"/mcp/{slug}", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert response.status_code in (400, 401, 404, 422), (slug, response.status_code)


def test_the_public_routes_return_no_internal_state(client: TestClient) -> None:
    for path in ("/health", "/healthz"):
        text = client.get(path).text
        assert SERVICE_TOKEN not in text and "organization" not in text.lower()
