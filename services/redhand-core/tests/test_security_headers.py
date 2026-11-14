"""
Response headers on every core answer (H3.2): nothing is sniffed as another type, nothing authenticated or token-bearing is cached by a
browser or a proxy, and browsers are told to stay on https. A route that sets its own Cache-Control (the event stream) keeps it.
"""

from __future__ import annotations

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from redhand_core.middleware.body_limit import BodySizeLimitMiddleware
from redhand_core.middleware.security_headers import SecurityHeadersMiddleware


def make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, default_limit=100)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/plain")
    async def plain() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/own-cache")
    async def own_cache(response: Response) -> dict[str, bool]:
        response.headers["Cache-Control"] = "no-cache"
        return {"ok": True}

    @app.post("/echo")
    async def echo() -> dict[str, bool]:
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
    client = TestClient(make_app())
    for response in (client.get("/missing"), client.post("/echo", content=b"x" * 500)):
        assert response.status_code in (404, 413)
        assert response.headers["x-content-type-options"] == "nosniff" and response.headers["cache-control"] == "no-store"


def test_the_real_app_sets_them_on_health_a_refusal_and_a_token_exchange() -> None:
    from redhand_core.main import create_app

    client = TestClient(create_app())
    for response in (
        client.get("/health"),
        client.get("/v1/passports"),  # refused: not signed in
        client.post("/v1/agent-auth/token", json={}),  # the token route
    ):
        assert response.headers["x-content-type-options"] == "nosniff", response.request.url
        assert response.headers["cache-control"] == "no-store", response.request.url
        assert "strict-transport-security" in response.headers, response.request.url
