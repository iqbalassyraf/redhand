"""
A request body is bounded before any handler reads it (H2.3, CLAUDE.md section 5.6). Without a global cap each route decides for itself, and a
route that forgets lets one client make core buffer an arbitrary body. The cap counts the bytes that actually arrive, so a chunked body with
no Content-Length (or a false one) is stopped too, and reading stops at the limit instead of after the whole body.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from redhand_core.middleware.body_limit import BodySizeLimitMiddleware

LIMIT = 1000


def make_app(limits: dict[str, int] | None = None) -> FastAPI:
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, default_limit=LIMIT, path_limits=limits or {})

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"bytes": len(await request.body())}

    @app.post("/big/echo")
    async def big(request: Request) -> dict[str, int]:
        return {"bytes": len(await request.body())}

    @app.get("/ping")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_a_body_within_the_limit_passes() -> None:
    client = TestClient(make_app())
    assert client.post("/echo", content=b"x" * LIMIT).json() == {"bytes": LIMIT}


def test_a_declared_length_over_the_limit_is_refused_with_413_and_a_stable_body() -> None:
    client = TestClient(make_app())
    response = client.post("/echo", content=b"x" * (LIMIT + 1))
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large."}


def test_a_chunked_body_without_a_length_is_stopped_at_the_limit() -> None:
    def chunks() -> Any:
        for _ in range(10):
            yield b"x" * 500

    client = TestClient(make_app())
    response = client.post("/echo", content=chunks())
    assert response.status_code == 413


def test_a_per_path_override_raises_the_limit_for_that_path_only() -> None:
    client = TestClient(make_app({"/big": 5000}))
    assert client.post("/big/echo", content=b"x" * 3000).json() == {"bytes": 3000}
    assert client.post("/big/echo", content=b"x" * 5001).status_code == 413
    assert client.post("/echo", content=b"x" * 3000).status_code == 413


def test_reads_never_carry_a_body_so_get_is_untouched() -> None:
    assert TestClient(make_app()).get("/ping").json() == {"ok": True}


def test_a_false_content_length_cannot_hide_a_larger_body() -> None:
    """Counting arriving bytes is what makes the cap hold; the header is only an early exit."""
    import asyncio

    app = make_app()
    sent: list[dict[str, Any]] = []
    pulled = 0

    async def receive() -> dict[str, Any]:
        nonlocal pulled
        pulled += 1
        return {"type": "http.request", "body": b"x" * 400, "more_body": pulled < 50}  # finite, so a missing safeguard fails instead of hanging

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http", "method": "POST", "path": "/echo", "raw_path": b"/echo", "query_string": b"", "root_path": "",
        "headers": [(b"content-length", b"10")], "scheme": "http", "server": ("test", 80), "client": ("c", 1), "http_version": "1.1",
    }
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413
    assert pulled <= 4, f"reading must stop soon after the limit, not run on (pulled {pulled} chunks)"


def test_the_real_app_refuses_an_oversized_body_before_authentication_runs() -> None:
    from redhand_core.main import create_app

    client = TestClient(create_app())
    response = client.post("/v1/telemetry/ingest", content=json.dumps({"pad": "x" * (2 * 1024 * 1024)}))
    assert response.status_code in (401, 403, 404, 405, 413, 422)
    huge = client.post("/internal/v1/events", content=b"x" * (20 * 1024 * 1024))
    assert huge.status_code == 413


def test_the_real_app_still_accepts_an_ingest_batch_larger_than_the_default_limit() -> None:
    from redhand_core.main import create_app

    client = TestClient(create_app())
    response = client.post("/internal/v1/events", content=b"{" + b" " * (2 * 1024 * 1024) + b"}")
    assert response.status_code != 413, "the ingest route has its own, larger limit"


@pytest.mark.parametrize("header", [b"abc", b"-5", b"1e3"])
def test_a_malformed_content_length_does_not_disable_the_count(header: bytes) -> None:
    import asyncio

    app = make_app()
    sent: list[dict[str, Any]] = []

    pulled = 0

    async def receive() -> dict[str, Any]:
        nonlocal pulled
        pulled += 1
        return {"type": "http.request", "body": b"x" * 600, "more_body": pulled < 50}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http", "method": "POST", "path": "/echo", "raw_path": b"/echo", "query_string": b"", "root_path": "",
        "headers": [(b"content-length", header)], "scheme": "http", "server": ("test", 80), "client": ("c", 1), "http_version": "1.1",
    }
    asyncio.run(app(scope, receive, send))
    assert next(m for m in sent if m["type"] == "http.response.start")["status"] == 413


def _scope(headers: list[tuple[bytes, bytes]]) -> dict[str, Any]:
    return {
        "type": "http", "method": "POST", "path": "/echo", "raw_path": b"/echo", "query_string": b"", "root_path": "",
        "headers": headers, "scheme": "http", "server": ("test", 80), "client": ("c", 1), "http_version": "1.1",
    }


def test_a_declared_length_over_the_limit_never_reaches_the_application() -> None:
    import asyncio

    called: list[bool] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        called.append(True)

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    app = BodySizeLimitMiddleware(inner, default_limit=LIMIT)
    asyncio.run(app(_scope([(b"content-length", str(LIMIT + 1).encode())]), receive, send))
    assert called == [] and sent[0]["status"] == 413


def test_an_application_that_ignores_the_disconnect_is_not_fed_more_of_the_body() -> None:
    import asyncio

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        for _ in range(20):  # keeps asking, whatever it is told
            await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"all good"})

    sent: list[dict[str, Any]] = []
    pulled = 0

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def receive() -> dict[str, Any]:
        nonlocal pulled
        pulled += 1
        return {"type": "http.request", "body": b"x" * 400, "more_body": pulled < 50}

    app = BodySizeLimitMiddleware(inner, default_limit=LIMIT)
    asyncio.run(app(_scope([]), receive, send))
    assert pulled == 3, f"the third chunk passes the limit and nothing is read after it (pulled {pulled})"
    assert [m.get("status") for m in sent if m["type"] == "http.response.start"] == [413], "the application's own answer is dropped"
