"""
MCP Scanner live scan, core side (Phase 4 M2): admins only, registered and active servers of the caller's organization only,
the URL comes from the database, the gateway is called with the service token, and nothing the server said reaches the
admin unsanitised.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID, uuid4

import httpx
from pydantic import SecretStr
import pytest

from redhand_core.routers import mcp_scan

from core_helpers import operator_headers
from test_telegram import Env as TelegramEnv

SERVICE_TOKEN = "scan-core-test-internal-service-token-0123456789"
OTHER_OWNER = "00000000-0000-0000-0000-0000000000f3"
SERVER_URL = "http://demo.test/mcp"


def _finding(i: int = 1, **over: Any) -> dict[str, Any]:
    base = {"id": "MCP-DESC-001", "severity": "HIGH", "category": "DESCRIPTION_RISK", "tool_name": f"tool_{i}",
            "title": "Description tells the agent to hide something from the user", "description": "fixed wording", "remediation": "Do not install."}
    base.update(over)
    return base


def _report(findings: list[dict[str, Any]] | None = None, verdict: str = "FAIL") -> dict[str, Any]:
    return {"report": {"server_name": "demo", "risk_score": 70, "verdict": verdict, "total_tools_scanned": 2,
                       "findings": [_finding()] if findings is None else findings, "recommended_policy": {}},
            "tool_count": 2, "truncated": False}


class FakeGateway:
    def __init__(self, status: int = 200, body: Any = None, error: Exception | None = None) -> None:
        self.status, self.body, self.error = status, body if body is not None else _report(), error
        self.calls: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.error:
            raise self.error
        if isinstance(self.body, (bytes, str)):
            return httpx.Response(self.status, content=self.body)
        return httpx.Response(self.status, json=self.body)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url="http://gateway.test", transport=httpx.MockTransport(self.handler))


class Env(TelegramEnv):
    def __init__(self, gateway: FakeGateway | None = None, configured: bool = True) -> None:
        extra: dict[str, Any] = {"INTERNAL_SERVICE_TOKEN": SecretStr(SERVICE_TOKEN), "ALLOW_INSECURE_MCP_URLS": True}
        if configured:
            extra["GATEWAY_URL"] = "http://gateway.test"
        super().__init__(**extra)
        self.gateway = gateway or FakeGateway()
        fake = self.gateway.client()

        async def override() -> Any:
            return fake if configured else None

        self.client.app.dependency_overrides[mcp_scan.get_gateway_client] = override  # type: ignore[attr-defined]

    def register(self, slug: str = "xero") -> dict[str, Any]:  # type: ignore[override]
        resp = self.client.post("/v1/mcp-servers", json={"slug": slug, "name": "Demo", "url": SERVER_URL}, headers=self.h("admin"))
        assert resp.status_code == 201, resp.text
        return dict(resp.json())

    def scan(self, server_id: str, user: str = "admin", **kwargs: Any) -> Any:
        return self.client.post(f"/v1/mcp-servers/{server_id}/scan", headers=self.h(user), **kwargs)

    def other_org_headers(self) -> dict[str, str]:
        return operator_headers(settings=self.settings, user_id=UUID(OTHER_OWNER))


@pytest.fixture
def env() -> Env:
    return Env()


def test_an_admin_scans_a_registered_server_and_the_gateway_is_called_with_the_database_url_and_service_token(env: Env) -> None:
    server = env.register()
    resp = env.scan(server["id"])
    body = resp.json()
    assert resp.status_code == 200 and body["verdict"] == "FAIL" and body["server_slug"] == "xero" and body["tool_count"] == 2
    assert body["findings"][0]["id"] == "MCP-DESC-001" and "cannot see" in body["limits"]
    (call,) = env.gateway.calls
    sent = json.loads(call.content)
    assert call.url.path == "/internal/v1/scan" and sent == {"server_url": SERVER_URL, "server_name": "xero"}
    assert call.headers["authorization"] == f"Bearer {SERVICE_TOKEN}"


def test_the_scan_names_the_operators_organization_so_the_gateway_limits_per_organization(env: Env) -> None:
    from redhand_core.services.local_store import DEFAULT_ORG_ID

    env.scan(env.register()["id"])
    (call,) = env.gateway.calls
    assert call.headers["x-redhand-organization"] == str(DEFAULT_ORG_ID)


@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 403), ("admin", 200), ("owner", 200)])
def test_only_admins_and_owners_can_scan(env: Env, user: str, expected: int) -> None:
    server = env.register()
    assert env.scan(server["id"], user).status_code == expected
    assert len(env.gateway.calls) == (1 if expected == 200 else 0)


def test_another_organizations_server_is_not_found_and_nothing_is_fetched(env: Env) -> None:
    server = env.register()
    resp = env.client.post(f"/v1/mcp-servers/{server['id']}/scan", headers=env.other_org_headers())
    assert resp.status_code == 404 and env.gateway.calls == []


def test_an_inactive_or_unknown_server_is_not_found(env: Env) -> None:
    server = env.register()
    env.client.post(f"/v1/mcp-servers/{server['id']}/deactivate", headers=env.h("admin"))
    assert env.scan(server["id"]).status_code == 404
    assert env.scan(str(uuid4())).status_code == 404
    assert env.scan("not-a-uuid").status_code == 422
    assert env.gateway.calls == []


def test_a_url_in_the_request_is_ignored(env: Env) -> None:
    server = env.register()
    env.scan(server["id"], json={"server_url": "http://169.254.169.254/latest", "url": "http://evil.test"})
    assert json.loads(env.gateway.calls[0].content)["server_url"] == SERVER_URL


def test_without_a_gateway_url_the_scan_is_unavailable_and_says_so() -> None:
    env = Env(configured=False)
    server = env.register()
    resp = env.scan(server["id"])
    assert resp.status_code == 503 and "not configured" in resp.json()["detail"]


@pytest.mark.parametrize(("gateway", "status_code"), [
    (FakeGateway(error=httpx.ConnectError("down")), 502),
    (FakeGateway(status=502, body={"detail": "Upstream MCP server is unreachable."}), 502),
    (FakeGateway(status=429, body={"detail": "slow down"}), 429),
    (FakeGateway(status=401, body={"detail": "no"}), 503),
    (FakeGateway(status=500, body="boom"), 502),
    (FakeGateway(status=200, body="not json"), 502),
    (FakeGateway(status=200, body={"report": {}}), 502),
])
def test_gateway_failures_become_clear_errors(gateway: FakeGateway, status_code: int) -> None:
    env = Env(gateway)
    server = env.register()
    assert env.scan(server["id"]).status_code == status_code


def test_a_server_failure_message_is_shown_but_sanitised() -> None:
    env = Env(FakeGateway(status=502, body={"detail": "Upstream‮ MCP​ server is unreachable.\x07"}))
    server = env.register()
    detail = env.scan(server["id"]).json()["detail"]
    assert "unreachable" in detail and "‮" not in detail and "​" not in detail and "\x07" not in detail


def test_untrusted_text_in_findings_is_stripped_and_capped_and_long_lists_are_cut() -> None:
    hostile = _finding(tool_name="evil‮tool\x00" + "n" * 500, title="T​itle " + "x" * 900, description="d" * 2000, remediation="r\x1b[31m" + "z" * 900)
    many = [hostile] + [_finding(i) for i in range(2, 260)]
    env = Env(FakeGateway(body=_report(many)))
    server = env.register()
    body = env.scan(server["id"]).json()
    first = body["findings"][0]
    assert len(body["findings"]) == mcp_scan.MAX_FINDINGS and body["findings_omitted"] == 259 - mcp_scan.MAX_FINDINGS
    assert "‮" not in first["tool_name"] and "\x00" not in first["tool_name"] and len(first["tool_name"]) <= 128
    assert "​" not in first["title"] and len(first["title"]) <= 200
    assert len(first["description"]) <= 400 and "\x1b" not in first["remediation"] and len(first["remediation"]) <= 300


def test_the_truncated_flag_and_a_passing_verdict_pass_through() -> None:
    body = _report([], "PASS")
    body["truncated"] = True
    env = Env(FakeGateway(body=body))
    server = env.register()
    result = env.scan(server["id"]).json()
    assert result["verdict"] == "PASS" and result["truncated"] is True and result["findings"] == []


def test_the_service_token_never_appears_in_responses_or_logs(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    server = env.register()
    with caplog.at_level(logging.DEBUG):
        resp = env.scan(server["id"])
    assert SERVICE_TOKEN not in resp.text and SERVICE_TOKEN not in caplog.text


def test_the_scan_is_not_recorded_as_a_control_action_and_changes_nothing(env: Env) -> None:
    server = env.register()
    before = len(env.store.tables.get("control_audit_log", []))
    env.scan(server["id"])
    assert len(env.store.tables.get("control_audit_log", [])) == before
    assert env.client.get("/v1/mcp-servers", headers=env.h("viewer")).json()[0]["is_active"] is True
