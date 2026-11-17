#!/usr/bin/env python3
"""
Black-box launch check: run it against a deployed RedHand before announcing it (docs/launch/owner-checklist.md).

It only sends unauthenticated or hostile requests and reads the answers, so it needs no credentials and changes nothing. It checks what a stranger on the internet
can see: that every protected route refuses, that no development shortcut is left on, the security headers, CORS, the body size limit and that errors leak nothing.
It does NOT check that the product works for a signed-in customer (that is docs/launch/first-customer-path.md) or anything inside the database.

  uv run python scripts/smoke_launch.py --core https://core.example.com [--gateway https://gateway.example.com] [--dashboard-origin https://app.example.com]
  uv run python scripts/smoke_launch.py --core http://127.0.0.1:8000 --allow-development     # local dev stack

Exit code 0 when every check passes, 1 otherwise. Lines starting WARN do not fail the run; they are things to read.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass

import httpx

TIMEOUT = 10.0
PROTECTED_GETS = ("/v1/passports", "/v1/state/snapshot", "/v1/organization/members", "/v1/organization/invites", "/v1/blackbox/events", "/v1/findings", "/v1/spend/agents")
PROTECTED_POSTS = ("/v1/passports", "/v1/organizations", "/v1/invites/accept", "/v1/passports/freeze-all")
INTERNAL = ("/internal/v1/signup-codes", "/internal/v1/gateway-context", "/internal/v1/events", "/metrics")
LEAK_MARKERS = ("Traceback", "File \"/", "site-packages", "/home/", "/app/", "psycopg", "postgrest", "SELECT ")


@dataclass
class Result:
    name: str
    ok: bool
    detail: str = ""
    warn: bool = False


def _b64(data: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _refused(status: int) -> bool:
    return status in (401, 403)


def check_core(client: httpx.Client, base: str, *, allow_development: bool, dashboard_origin: str | None) -> list[Result]:
    out: list[Result] = []

    def add(name: str, ok: bool, detail: str = "", warn: bool = False) -> None:
        out.append(Result(name, ok, detail, warn))

    def call(method: str, path: str, **kwargs: object) -> httpx.Response | None:
        try:
            return client.request(method, base + path, **kwargs)  # type: ignore[arg-type]
        except httpx.HTTPError as exc:
            add(f"{method} {path} answers", False, type(exc).__name__)
            return None

    health = call("GET", "/health")
    if health is not None:
        body = health.json() if health.headers.get("content-type", "").startswith("application/json") else {}
        add("core /health is 200", health.status_code == 200, f"status {health.status_code}")
        env = body.get("environment")
        add("core is not in development mode", allow_development or env != "development", f"environment={env!r}")
        headers = {k.lower(): v for k, v in health.headers.items()}
        add("core sends X-Content-Type-Options: nosniff", headers.get("x-content-type-options") == "nosniff")
        add("core sends Cache-Control: no-store", "no-store" in headers.get("cache-control", ""))
        if base.startswith("https://"):
            add("core sends Strict-Transport-Security", "max-age=" in headers.get("strict-transport-security", ""))
        else:
            add("core is served over https", allow_development, "plain http", warn=allow_development)

    for path in PROTECTED_GETS:
        r = call("GET", path)
        if r is not None:
            add(f"GET {path} refuses a stranger", _refused(r.status_code), f"status {r.status_code}")
    for path in PROTECTED_POSTS:
        r = call("POST", path, json={})
        if r is not None:
            add(f"POST {path} refuses a stranger", _refused(r.status_code), f"status {r.status_code}")
    for path in INTERNAL:
        r = call("GET", path)
        if r is not None:
            add(f"{path} refuses a stranger", r.status_code in (401, 403, 404, 405, 503), f"status {r.status_code}")

    for label, token in (
        ("a garbage token", "not-a-token"),
        ("an unsigned (alg none) token", f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '00000000-0000-0000-0000-000000000001', 'aud': 'authenticated', 'exp': 4102444800})}."),
        ("a token signed with the wrong key", f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64({'sub': '00000000-0000-0000-0000-000000000001', 'aud': 'authenticated', 'exp': 4102444800})}.{'A' * 43}"),
    ):
        r = call("GET", "/v1/passports", headers={"Authorization": f"Bearer {token}"})
        if r is not None:
            add(f"{label} is refused", r.status_code == 401, f"status {r.status_code}")

    dev = call("POST", "/v1/dev/login", json={"user": "owner"})
    if dev is not None:
        add("the development login does not exist", allow_development or dev.status_code in (404, 405), f"status {dev.status_code}")

    r = call("OPTIONS", "/v1/passports", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    if r is not None:
        add("CORS does not allow a foreign origin", r.headers.get("access-control-allow-origin") not in ("*", "https://evil.example"), f"allow-origin={r.headers.get('access-control-allow-origin')!r}")
    if dashboard_origin:
        r = call("OPTIONS", "/v1/passports", headers={"Origin": dashboard_origin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
        if r is not None:
            add("CORS allows the dashboard origin", r.headers.get("access-control-allow-origin") == dashboard_origin, f"allow-origin={r.headers.get('access-control-allow-origin')!r}")

    r = call("POST", "/v1/organizations", content=b"x" * (2 * 1024 * 1024 + 1), headers={"Content-Type": "application/json"})
    if r is not None:
        add("an oversize body is refused before it is read", r.status_code == 413, f"status {r.status_code}")

    r = call("GET", "/v1/this-route-does-not-exist")
    if r is not None:
        add("an unknown route is a plain 404", r.status_code == 404 and not any(m in r.text for m in LEAK_MARKERS), f"status {r.status_code}")
    r = call("POST", "/v1/organizations", content=b"{not json", headers={"Content-Type": "application/json"})
    if r is not None:
        add("a malformed request leaks no internals", not any(m in r.text for m in LEAK_MARKERS), f"status {r.status_code}")

    docs = call("GET", "/docs")
    if docs is not None and docs.status_code == 200:
        add("API documentation is publicly reachable", True, "/docs answers 200: not a secret (the repository is public) but a stranger can browse the routes", warn=True)
    return out


def check_gateway(client: httpx.Client, base: str) -> list[Result]:
    out: list[Result] = []
    try:
        health = client.get(base + "/health")
        out.append(Result("gateway /health is 200", health.status_code == 200, f"status {health.status_code}"))
        call = client.post(base + "/mcp/anything", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        out.append(Result("gateway refuses an MCP call with no agent token", _refused(call.status_code), f"status {call.status_code}"))
        metrics = client.get(base + "/metrics")
        out.append(Result("gateway /metrics refuses a stranger", metrics.status_code in (401, 403, 503), f"status {metrics.status_code}"))
        audit = client.get(base + "/v1/audit/logs")
        out.append(Result("gateway audit log refuses a stranger", _refused(audit.status_code), f"status {audit.status_code}"))
    except httpx.HTTPError as exc:
        out.append(Result("gateway answers", False, type(exc).__name__))
    return out


def report(results: list[Result], printer: Callable[[str], None] = print) -> int:
    failed = 0
    for r in results:
        label = "PASS" if r.ok and not r.warn else ("WARN" if r.warn else "FAIL")
        failed += label == "FAIL"
        printer(f"{label}  {r.name}" + (f"  ({r.detail})" if r.detail and label != "PASS" else ""))
    printer(f"\n{sum(r.ok and not r.warn for r in results)} passed, {sum(r.warn for r in results)} warnings, {failed} failed")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--core", required=True, help="base URL of redhand-core")
    parser.add_argument("--gateway", help="base URL of the AgentWall gateway")
    parser.add_argument("--dashboard-origin", help="the dashboard's origin, to check CORS allows it")
    parser.add_argument("--allow-development", action="store_true", help="accept development mode and plain http (local stack only)")
    args = parser.parse_args(argv)
    with httpx.Client(follow_redirects=False, timeout=TIMEOUT) as client:
        results = check_core(client, args.core.rstrip("/"), allow_development=args.allow_development, dashboard_origin=args.dashboard_origin)
        if args.gateway:
            results += check_gateway(client, args.gateway.rstrip("/"))
    return report(results)


if __name__ == "__main__":
    sys.exit(main())
