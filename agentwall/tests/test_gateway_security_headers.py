"""
Response headers on every gateway answer (H3.2): nothing is sniffed as another type, no tool answer or token-bearing response is cached, and
browsers are told to stay on https. A route that sets its own Cache-Control keeps it.
"""

from __future__ import annotations

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from agentwall.src.gateway.security_headers import SecurityHeadersMiddleware


def make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/plain")
    async def plain() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/own-cache")
    async def own_cache(response: Response) -> dict[str, bool]:
        response.headers["Cache-Control"] = "no-cache"
        return {"ok": True}

    return app


def test_every_answer_carries_the_fixed_headers() -> None:
    response = TestClient(make_app()).get("/plain")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert "max-age=" in response.headers["strict-transport-security"]


def test_a_route_that_sets_its_own_cache_control_keeps_it() -> None:
    assert TestClient(make_app()).get("/own-cache").headers["cache-control"] == "no-cache"


def test_error_answers_carry_them_too() -> None:
    response = TestClient(make_app()).get("/missing")
    assert response.status_code == 404
    assert response.headers["x-content-type-options"] == "nosniff" and response.headers["cache-control"] == "no-store"


def test_the_real_gateway_sets_them_on_health_a_refusal_and_a_tool_call() -> None:
    from agentwall.src.main import app

    client = TestClient(app)
    for response in (
        client.get("/health"),
        client.post("/mcp/xero", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),  # no token: refused
        client.get("/v1/policies"),  # no service token: refused
    ):
        assert response.headers["x-content-type-options"] == "nosniff", response.request.url
        assert response.headers["cache-control"] == "no-store", response.request.url
        assert "strict-transport-security" in response.headers, response.request.url
