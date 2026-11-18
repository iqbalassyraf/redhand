"""
Passport enforcement at the MCP gateway (Phase 1, M4). Covers "done" test 2 (in-scope
call succeeds, out-of-scope call denied and logged) and the gateway side of done tests
3 and 4 (frozen / revoked agents denied within the revocation SLO).

Core and the customer's MCP server are replaced with in-process fakes (httpx
MockTransport). Tokens are signed with a test Ed25519 key in the same format core uses.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import time
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
from httpx import ASGITransport, AsyncClient
import jwt
import pytest

from agentwall.src import main as gateway_main
from agentwall.src.gateway.budget import BudgetMeter
from agentwall.src.gateway.context import CoreContextClient
from agentwall.src.gateway.identity import AgentTokenVerifier
from agentwall.src.gateway.metrics import GatewayMetrics
from agentwall.src.gateway.recorder import EventRecorder
from agentwall.src.gateway.pins import PinCoordinator, PinReport
from agentwall.src.gateway.radar_scan import FindingsReport, RadarScanner, ScanCountsReport
from agentwall.src.gateway.trips import Outcome, Trip, TripDispatcher
from agentwall.src.gateway.service import (
    JSONRPC_GATEWAY_UNAVAILABLE,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PASSPORT_INACTIVE,
    JSONRPC_POLICY_VIOLATION,
    JSONRPC_UNAUTHORIZED,
    JSONRPC_UNKNOWN_SERVER,
    JSONRPC_UPSTREAM_UNAVAILABLE,
    McpGateway,
)
from agentwall.src.gateway.upstream import (
    DestinationBlockedError,
    UpstreamForwarder,
    check_destination,
    parse_sse_messages,
)

ORG = UUID("00000000-0000-0000-0000-000000000010")
OTHER_ORG = UUID("00000000-0000-0000-0000-0000000000f0")
SERVICE_TOKEN = "svc-token-for-tests-0123456789"
UPSTREAM_URL = "https://mcp.example.com/xero"


class FakeReporter:
    """Stands in for core's /internal/v1/usage."""

    def __init__(self) -> None:
        self.reports: list[list[dict[str, Any]]] = []
        self.accept = True
        self.crash = False

    async def send(self, instance_id: str, items: list[dict[str, Any]]) -> bool:
        if self.crash:
            raise RuntimeError("reporter exploded")
        self.reports.append(items)
        return self.accept


class FakeTripReporter:
    """Stands in for core's /internal/v1/trips."""

    def __init__(self) -> None:
        self.trips: list[Trip] = []
        self.outcomes: list[Outcome] = []  # answers to give in order; "ok" once they run out

    async def send(self, trip: Trip) -> Outcome:
        self.trips.append(trip)
        return self.outcomes.pop(0) if self.outcomes else "ok"


class FakePinReporter:
    """Stands in for core's /internal/v1/tool-observations."""

    def __init__(self) -> None:
        self.reports: list[PinReport] = []
        self.outcomes: list[Outcome] = []

    async def send(self, report: PinReport) -> Outcome:
        self.reports.append(report)
        return self.outcomes.pop(0) if self.outcomes else "ok"


class FakeFindingsReporter:
    """Stands in for core's /internal/v1/findings."""

    def __init__(self) -> None:
        self.reports: list[FindingsReport] = []
        self.outcomes: list[Outcome] = []

    async def send(self, report: FindingsReport) -> Outcome:
        self.reports.append(report)
        return self.outcomes.pop(0) if self.outcomes else "ok"


class FakeScanCountsReporter:
    """Stands in for core's /internal/v1/radar/scan-counts."""

    def __init__(self) -> None:
        self.reports: list[ScanCountsReport] = []
        self.outcomes: list[Outcome] = []

    async def send(self, report: ScanCountsReport) -> Outcome:
        self.reports.append(report)
        return self.outcomes.pop(0) if self.outcomes else "ok"


class FakeEventReporter:
    """Stands in for core's /internal/v1/events."""

    def __init__(self) -> None:
        self.batches: list[list[dict[str, Any]]] = []
        self.accept = True
        self.crash = False

    async def send(self, instance_id: str, batch_id: str, organization_id: UUID, items: list[dict[str, Any]]) -> bool:
        if self.crash:
            raise RuntimeError("event reporter exploded")
        self.batches.append(items)
        return self.accept

    @property
    def events(self) -> list[dict[str, Any]]:
        return [item for batch in self.batches for item in batch]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class FakeCore:
    """Stands in for redhand-core's /internal/v1/gateway-context."""

    agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    servers: dict[tuple[str, str], str] = field(default_factory=dict)
    pins: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)  # (org, server) -> {"mode", "approved"}
    calls: int = 0
    mode: str = "ok"  # ok | down | error | malformed | mismatch

    def _pin_fields(self, org: str, server: str) -> dict[str, Any]:
        pin = self.pins.get((org, server), {"mode": "alert", "approved": []})
        return {"pin_mode": pin["mode"], "approved_tools": [{"tool": t, "digest": d} for t, d in pin["approved"]]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.mode == "down":
            raise httpx.ConnectError("refused", request=request)
        if self.mode == "error":
            return httpx.Response(500)
        if self.mode == "malformed":
            return httpx.Response(200, content=b"not json")
        if request.headers.get("authorization") != f"Bearer {SERVICE_TOKEN}":
            return httpx.Response(401)
        q = request.url.params
        agent = self.agents.get(q["agent_id"])
        if agent is None or agent["organization_id"] != q["organization_id"]:
            return httpx.Response(404)
        url = self.servers.get((q["organization_id"], q["server"]))
        body = {
            "agent": {**agent, "id": str(uuid4()) if self.mode == "mismatch" else agent["id"]},
            "server": {"slug": q["server"], "url": url, **self._pin_fields(q["organization_id"], q["server"])} if url else None,
        }
        return httpx.Response(200, json=body)


@dataclass
class FakeUpstream:
    """A customer MCP server that records what it receives."""

    received: list[dict[str, Any]] = field(default_factory=list)
    headers: list[dict[str, str]] = field(default_factory=list)
    mode: str = "json"  # json | sse | down | error | redirect | huge | wrong_id
    reply_text: str | None = None  # what a tools/call returns, when a test needs specific content

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.mode == "down":
            raise httpx.ConnectError("refused", request=request)
        message = json.loads(request.content)
        self.received.append(message)
        self.headers.append(dict(request.headers))
        if self.mode == "error":
            return httpx.Response(500, json={"oops": True})
        if self.mode == "redirect":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/"})
        if "id" not in message:
            return httpx.Response(202)
        if self.mode == "huge":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": {"x": "a" * 20_000}})
        result: Any
        method = message["method"]
        if method == "tools/list":
            result = {"tools": [{"name": n, "inputSchema": {}} for n in ("list_invoices", "delete_invoice", "execute_sql")]}
        elif method == "tools/call":
            name = message["params"]["name"]
            text = self.reply_text or ("leaked key AKIAIOSFODNN7EXAMPLE" if name == "leaky" else f"ran {name}")
            result = {"content": [{"type": "text", "text": text}]}
        else:
            result = {"protocolVersion": "2025-06-18", "capabilities": {}}
        reply = {"jsonrpc": "2.0", "id": "other" if self.mode == "wrong_id" else message["id"], "result": result}
        if self.mode == "sse":
            notice = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
            body = f"event: message\ndata: {json.dumps(notice)}\n\nevent: message\ndata: {json.dumps(reply)}\n\n"
            return httpx.Response(200, text=body, headers={"content-type": "text/event-stream", "mcp-session-id": "s-1"})
        return httpx.Response(200, json=reply, headers={"mcp-session-id": "s-1"})


class Harness:
    def __init__(self, ttl: float = 2.0, max_response_bytes: int = 1_000_000, service_token: str | None = SERVICE_TOKEN) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        public_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.core = FakeCore()
        self.upstream = FakeUpstream()
        self.clock = FakeClock()
        self.reporter = FakeReporter()
        self.budget = BudgetMeter(instance_id="test-gateway-0001", reporter=self.reporter, clock=self.clock, jitter=lambda: 0.5)
        self.event_reporter = FakeEventReporter()
        self.recorder = EventRecorder(instance_id="test-gateway-0001", reporter=self.event_reporter)
        self._decisions: list[dict[str, Any]] = []
        record_event = self.recorder.record

        def capture_and_record(event: Any) -> None:
            self._decisions.append(asdict(event))
            record_event(event)

        self.recorder.record = capture_and_record  # type: ignore[method-assign]  # test spy: every decision the gateway hands to the Black Box recorder
        self.trip_reporter = FakeTripReporter()
        self.trips = TripDispatcher(reporter=self.trip_reporter, retry_delays=())
        self.pin_reporter = FakePinReporter()
        self.pins = PinCoordinator(reporter=self.pin_reporter, retry_delays=())
        self.findings_reporter = FakeFindingsReporter()
        self.counts_reporter = FakeScanCountsReporter()
        self.metrics = GatewayMetrics()
        self.radar = RadarScanner(
            reporter=self.findings_reporter, metrics=self.metrics, retry_delays=(), counts_reporter=self.counts_reporter,
            fingerprint="0123456789abcdef",
        )
        self.gateway = McpGateway(
            verifier=AgentTokenVerifier(public_key_pem=public_pem, jwks_url=None),
            contexts=CoreContextClient(
                core_url="http://core", service_token=service_token, ttl_seconds=ttl, instance_id="test-gateway-0001",
                http_client=httpx.AsyncClient(transport=httpx.MockTransport(self.core.handler)),
                clock=self.clock,
            ),
            forwarder=UpstreamForwarder(
                allow_insecure=True, max_response_bytes=max_response_bytes, connect_timeout=1, total_timeout=5,
                http_client=httpx.AsyncClient(transport=httpx.MockTransport(self.upstream.handler)),
            ),
            firewall=gateway_main.firewall_engine,
            metrics=self.metrics,
            budget=self.budget,
            recorder=self.recorder,
            trips=self.trips,
            pins=self.pins,
            radar=self.radar,
        )

    def decisions(self, limit: int = 50) -> list[dict[str, Any]]:
        """The decisions the gateway reported to the Black Box (the one audit trail, ADR 0030), oldest first, last `limit`."""
        return self._decisions[-limit:]

    def full_rows(self, limit: int = 200) -> list[dict[str, Any]]:
        """Only the full rows (argument digest present). A repeated refusal inside its minute is reported as a slim row without one."""
        return [d for d in self._decisions if d["arguments_sha256"]][-limit:]

    def add_agent(
        self, scopes: list[dict[str, str]], status: str = "active", org: UUID = ORG, safe_mode: bool = False,
        limit: int | None = None, used_by_others: int = 0, payload_capture: bool = False,
        honeytokens: list[dict[str, str]] | None = None, honey_tools: list[dict[str, str]] | None = None,
        radar_mode: str = "off", output_check_mode: str = "off",
        loop_mode: str = "off", loop_limit: int = 20, loop_window_seconds: int = 60, loop_exempt: bool = False,
        destination_mode: str = "off", allowed_destinations: tuple[str, ...] = (), model_spend: dict[str, Any] | None = None,
    ) -> UUID:
        agent_id = uuid4()
        self.core.agents[str(agent_id)] = {
            "id": str(agent_id), "organization_id": str(org), "status": status, "version": 1,
            "scopes": scopes, "expires_at": "2099-01-01T00:00:00+00:00", "safe_mode": safe_mode,
            "payload_capture": payload_capture,
            "honeytokens": honeytokens or [], "honey_tools": honey_tools or [],
            "radar_mode": radar_mode, "output_check_mode": output_check_mode,
            "loop_mode": loop_mode, "loop_limit": loop_limit, "loop_window_seconds": loop_window_seconds, "loop_exempt": loop_exempt,
            "destination_mode": destination_mode, "allowed_destinations": list(allowed_destinations),
            "model_spend": model_spend,
            "budget": {
                "daily_call_limit": limit, "used_by_other_instances": used_by_others, "day_key": "2026-11-04",
                "resets_at": "2026-11-04T16:00:00+00:00", "action": "deny",
            },
        }
        self.core.servers[(str(org), "xero")] = UPSTREAM_URL
        return agent_id

    def token(self, agent_id: UUID, org: UUID = ORG, key: Any = None, **overrides: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": "redhand-core", "aud": "redhand-gateway", "sub": str(agent_id), "org": str(org),
            "ver": 1, "jti": uuid4().hex, "iat": now, "nbf": now, "exp": now + 600,
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key or self.private_key, algorithm="EdDSA")

    async def call(
        self, token: str | None, method: str = "tools/call", params: dict[str, Any] | None = None,
        server: str = "xero", message: Any = None, upstream_auth: str | None = None,
    ) -> Any:
        msg = message if message is not None else {"jsonrpc": "2.0", "id": 7, "method": method, "params": params or {}}
        return await self.gateway.handle(
            server=server, message=msg, bearer_token=token, client_headers={}, upstream_authorization=upstream_auth,
        )


def tool(name: str, **args: Any) -> dict[str, Any]:
    return {"name": name, "arguments": args}


INVOICES_READ = [{"server": "xero", "tool": "list_invoices", "access": "read"}]


# ---------------------------------------------------------------------------
# Agent authentication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_or_invalid_tokens_are_rejected() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    other_key = Ed25519PrivateKey.generate()
    bad_tokens = [
        None,
        "garbage",
        h.token(agent, key=other_key),
        h.token(agent, exp=int(time.time()) - 120, iat=int(time.time()) - 900, nbf=int(time.time()) - 900),
        h.token(agent, aud="someone-else"),
        h.token(agent, iss="evil"),
        h.token(agent, org=None),
        h.token(agent, sub="not-a-uuid"),
        jwt.encode({"sub": str(agent), "org": str(ORG)}, "secret-secret-secret-secret-secret!", algorithm="HS256"),
    ]
    for bad in bad_tokens:
        resp = await h.call(bad, params=tool("list_invoices"))
        assert resp.status_code == 401, bad
        assert resp.body["error"]["code"] == JSONRPC_UNAUTHORIZED
    assert h.upstream.received == []


@pytest.mark.asyncio
async def test_token_for_unknown_agent_or_wrong_tenant_is_rejected() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    assert (await h.call(h.token(uuid4()), params=tool("list_invoices"))).status_code == 401
    assert (await h.call(h.token(agent, org=OTHER_ORG), params=tool("list_invoices"))).status_code == 401
    assert h.upstream.received == []


# ---------------------------------------------------------------------------
# Done test 2: in-scope allowed, out-of-scope denied and logged
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_in_scope_tool_call_is_forwarded_and_audited() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    resp = await h.call(token, params=tool("list_invoices", month="2026-10"), upstream_auth="Bearer xero-api-key")
    assert resp.status_code == 200
    assert resp.body["result"]["content"][0]["text"] == "ran list_invoices"
    assert resp.headers.get("mcp-session-id") == "s-1"

    forwarded_headers = h.upstream.headers[0]
    assert forwarded_headers["authorization"] == "Bearer xero-api-key"
    assert token not in json.dumps(forwarded_headers)

    record = h.decisions(1)[-1]
    assert record["decision"] == "ALLOW"
    assert str(record["organization_id"]) == str(ORG) and record["server"] == "xero"
    assert record["tool_name"] == "list_invoices" and record["argument_keys"] == ["month"]
    assert "2026-10" not in json.dumps(record, default=str)


@pytest.mark.asyncio
async def test_out_of_scope_tool_call_is_denied_and_logged() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    resp = await h.call(h.token(agent), params=tool("delete_invoice", id="INV-1"))
    assert resp.status_code == 200
    assert resp.body["error"]["code"] == JSONRPC_POLICY_VIOLATION
    assert "out of scope" in resp.body["error"]["message"]
    assert h.upstream.received == []
    record = h.decisions(1)[-1]
    assert record["decision"] == "BLOCK" and record["tool_name"] == "delete_invoice"
    assert "not in this agent's passport scopes" in record["reasons"][0]


@pytest.mark.asyncio
async def test_scope_wildcards_and_server_binding() -> None:
    h = Harness()
    wildcard = h.add_agent([{"server": "xero", "tool": "*", "access": "write"}])
    other_server = h.add_agent([{"server": "github", "tool": "list_invoices", "access": "read"}])
    assert "result" in (await h.call(h.token(wildcard), params=tool("delete_invoice"))).body
    denied = await h.call(h.token(other_server), params=tool("list_invoices"))
    assert denied.body["error"]["code"] == JSONRPC_POLICY_VIOLATION


@pytest.mark.asyncio
async def test_tools_list_is_filtered_to_permitted_tools() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    resp = await h.call(h.token(agent), method="tools/list")
    assert [t["name"] for t in resp.body["result"]["tools"]] == ["list_invoices"]


@pytest.mark.asyncio
async def test_guardrails_still_apply_to_in_scope_tools() -> None:
    h = Harness()
    agent = h.add_agent([{"server": "xero", "tool": "execute_sql", "access": "write"}])
    resp = await h.call(h.token(agent), params=tool("execute_sql", query="DROP TABLE invoices;"))
    assert resp.body["error"]["code"] == JSONRPC_POLICY_VIOLATION
    assert any("drop" in v.lower() for v in resp.body["error"]["data"]["violations"])
    assert h.upstream.received == []


@pytest.mark.asyncio
async def test_secrets_in_tool_results_are_redacted() -> None:
    h = Harness()
    agent = h.add_agent([{"server": "xero", "tool": "leaky", "access": "read"}])
    resp = await h.call(h.token(agent), params=tool("leaky"))
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(resp.body)


@pytest.mark.asyncio
async def test_only_governed_methods_are_forwarded() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    for method in ("resources/read", "prompts/get", "sampling/createMessage", "tools/delete"):
        resp = await h.call(token, method=method)
        assert resp.body["error"]["code"] == JSONRPC_METHOD_NOT_FOUND, method
    assert h.upstream.received == []
    for method in ("initialize", "ping"):
        assert "result" in (await h.call(token, method=method)).body
    note = await h.call(token, message={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert note.status_code == 202 and note.body is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [[{"jsonrpc": "2.0", "id": 1, "method": "ping"}], {"id": 1, "method": "ping"}, {"jsonrpc": "2.0", "id": 1}, None, "x"],
)
async def test_malformed_messages_are_rejected(message: Any) -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    resp = await h.gateway.handle(server="xero", message=message, bearer_token=h.token(agent), client_headers={}, upstream_authorization=None)
    assert resp.status_code == 400
    assert h.upstream.received == []


@pytest.mark.asyncio
async def test_tools_call_requires_valid_params() -> None:
    h = Harness()
    token = h.token(h.add_agent(INVOICES_READ))
    for params in ({}, {"name": ""}, {"name": 5}, {"name": "list_invoices", "arguments": [1]}):
        assert (await h.call(token, params=params)).body["error"]["code"] == -32602
    assert h.upstream.received == []


@pytest.mark.asyncio
async def test_unknown_server_is_rejected() -> None:
    h = Harness()
    agent = h.add_agent([{"server": "github", "tool": "*", "access": "read"}])
    resp = await h.call(h.token(agent), params=tool("x"), server="github")
    assert resp.status_code == 404 and resp.body["error"]["code"] == JSONRPC_UNKNOWN_SERVER


# ---------------------------------------------------------------------------
# Done tests 3 & 4 at the gateway: inactive passports are denied
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["frozen", "revoked", "expired"])
async def test_inactive_passports_are_denied(status: str) -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, status=status)
    for method in ("tools/call", "tools/list", "initialize"):
        resp = await h.call(h.token(agent), method=method, params=tool("list_invoices"))
        assert resp.status_code == 403
        assert resp.body["error"]["code"] == JSONRPC_PASSPORT_INACTIVE
        assert resp.body["error"]["data"]["passport_status"] == status
    assert h.upstream.received == []
    assert h.decisions(1)[0]["reasons"] == [f"passport_{status}"]


@pytest.mark.asyncio
async def test_revocation_reaches_gateway_within_slo_even_with_valid_token() -> None:
    """A still-valid access token stops working once the cache window passes (<= 5 s)."""
    h = Harness(ttl=2.0)
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body

    h.core.agents[str(agent)]["status"] = "revoked"  # revoke happens in core
    h.clock.now += 1.0
    cached = await h.call(token, params=tool("list_invoices"))  # inside the cache window
    h.clock.now += 1.01
    after = await h.call(token, params=tool("list_invoices"))
    assert "result" in cached.body
    assert after.status_code == 403
    assert h.gateway.contexts._ttl + 0 <= 4.0  # configuration cannot exceed the SLO budget


@pytest.mark.asyncio
async def test_freeze_all_blocks_every_agent_of_tenant() -> None:
    h = Harness(ttl=0.0)
    agents = [h.add_agent(INVOICES_READ) for _ in range(3)]
    tokens = [h.token(a) for a in agents]
    for t in tokens:
        assert "result" in (await h.call(t, params=tool("list_invoices"))).body
    for a in agents:
        h.core.agents[str(a)]["status"] = "frozen"
    for t in tokens:
        assert (await h.call(t, params=tool("list_invoices"))).status_code == 403


def test_context_ttl_is_capped_to_meet_revocation_slo() -> None:
    client = CoreContextClient(core_url="http://core", service_token="x", ttl_seconds=60, instance_id="test-gateway-0001")
    # The cap itself moved from 4 s to 2.5 s in D1 PR 4 (a hanging core must still be refused within 4.5 s: see test_context_refresh.py); what this proves is the clamp.
    assert client._ttl == 2.5


# ---------------------------------------------------------------------------
# Fail closed when core is unavailable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["down", "error", "malformed", "mismatch"])
async def test_core_failures_deny(mode: str) -> None:
    h = Harness(ttl=0.0)
    agent = h.add_agent(INVOICES_READ)
    h.core.mode = mode
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert resp.status_code == 503
    assert resp.body["error"]["code"] == JSONRPC_GATEWAY_UNAVAILABLE
    assert h.upstream.received == []


@pytest.mark.asyncio
async def test_core_failure_is_not_cached_as_allow() -> None:
    h = Harness(ttl=2.0)
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    h.core.mode = "down"
    assert (await h.call(token, params=tool("list_invoices"))).status_code == 503
    h.core.mode = "ok"
    assert "result" in (await h.call(token, params=tool("list_invoices"))).body


@pytest.mark.asyncio
async def test_missing_service_token_denies_everything() -> None:
    h = Harness(service_token=None)
    agent = h.add_agent(INVOICES_READ)
    assert (await h.call(h.token(agent), params=tool("list_invoices"))).status_code == 503
    assert h.core.calls == 0


# ---------------------------------------------------------------------------
# Upstream handling: errors never become success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["down", "error", "redirect", "huge", "wrong_id"])
async def test_upstream_failures_return_errors(mode: str) -> None:
    h = Harness(max_response_bytes=10_000)
    agent = h.add_agent(INVOICES_READ)
    h.upstream.mode = mode
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert resp.status_code == 502
    assert resp.body["error"]["code"] == JSONRPC_UPSTREAM_UNAVAILABLE
    assert "result" not in resp.body
    assert h.decisions(1)[0]["decision"] == "ERROR"


@pytest.mark.asyncio
async def test_sse_upstream_responses_are_supported() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    h.upstream.mode = "sse"
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert resp.status_code == 200 and resp.body["result"]["content"][0]["text"] == "ran list_invoices"


def test_parse_sse_messages_ignores_noise() -> None:
    body = 'event: x\ndata: {"a": 1}\n\n: comment\n\ndata: not-json\n\ndata: {"b":\ndata: 2}\n\n'
    assert parse_sse_messages(body) == [{"a": 1}, {"b": 2}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://mcp.example.com/x",
        "https://127.0.0.1/x",
        "https://10.1.2.3/x",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/x",
        "https://user:pw@8.8.8.8/x",
        "ftp://8.8.8.8/x",
    ],
)
async def test_destination_check_blocks_unsafe_upstreams(url: str) -> None:
    with pytest.raises(DestinationBlockedError):
        await check_destination(url, allow_insecure=False)


@pytest.mark.asyncio
async def test_destination_check_allows_public_https() -> None:
    await check_destination("https://8.8.8.8/mcp", allow_insecure=False)


@pytest.mark.asyncio
async def test_private_upstream_is_blocked_end_to_end() -> None:
    h = Harness()
    h.gateway.forwarder._allow_insecure = False
    agent = h.add_agent(INVOICES_READ)
    h.core.servers[(str(ORG), "xero")] = "https://169.254.169.254/latest"
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert resp.status_code == 502
    assert h.upstream.received == []


# ---------------------------------------------------------------------------
# Token keys from core's JWKS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jwks_key_discovery_and_failure() -> None:
    private = Ed25519PrivateKey.generate()
    jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": "k1", "alg": "EdDSA", "use": "sig"})
    state = {"up": True, "fetches": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["fetches"] += 1
        if not state["up"]:
            raise httpx.ConnectError("down", request=request)
        return httpx.Response(200, json={"keys": [jwk]})

    verifier = AgentTokenVerifier(
        public_key_pem=None, jwks_url="http://core/v1/agent-auth/jwks",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    now = int(time.time())
    claims = {"iss": "redhand-core", "aud": "redhand-gateway", "sub": str(uuid4()), "org": str(ORG),
              "ver": 3, "jti": "j", "iat": now, "exp": now + 60}
    identity = await verifier.verify(jwt.encode(claims, private, algorithm="EdDSA", headers={"kid": "k1"}))
    assert identity.passport_version == 3 and state["fetches"] == 1

    from agentwall.src.gateway.identity import AgentAuthError, KeyUnavailableError

    with pytest.raises(AgentAuthError):
        await verifier.verify(jwt.encode(claims, private, algorithm="EdDSA", headers={"kid": "unknown"}))

    cold = AgentTokenVerifier(
        public_key_pem=None, jwks_url="http://core/jwks",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    state["up"] = False
    with pytest.raises(KeyUnavailableError):
        await cold.verify(jwt.encode(claims, private, algorithm="EdDSA", headers={"kid": "k1"}))


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_endpoint_and_operational_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    monkeypatch.setattr(gateway_main, "gateway", h.gateway)
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": tool("list_invoices")}
    async with AsyncClient(transport=ASGITransport(app=gateway_main.app), base_url="http://test") as client:
        ok = await client.post("/mcp/xero", json=message, headers={"Authorization": f"Bearer {h.token(agent)}"})
        anon = await client.post("/mcp/xero", json=message)
        bad_slug = await client.post("/mcp/Not_A_Slug", json=message)
        stream = await client.get("/mcp/xero")
        too_big = await client.post(
            "/mcp/xero", content=b"x" * (gateway_main.settings.MAX_REQUEST_BYTES + 1),
            headers={"Authorization": f"Bearer {h.token(agent)}"},
        )
        legacy = await client.post("/mcp", json=message, headers={"X-User-Roles": "admin"})
        ops = [await client.get(p) for p in ("/v1/policies", "/metrics")]
    assert ok.status_code == 200 and "result" in ok.json()
    assert anon.status_code == 401 and anon.headers["www-authenticate"].startswith("Bearer")
    assert bad_slug.status_code == 422
    assert stream.status_code == 405
    assert too_big.status_code == 413
    assert legacy.status_code in (404, 405)
    assert all(r.status_code == 401 for r in ops)


@pytest.mark.asyncio
async def test_operational_endpoints_accept_service_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import SecretStr

    monkeypatch.setattr(gateway_main.settings, "CORE_SERVICE_TOKEN", SecretStr(SERVICE_TOKEN))
    h = Harness()
    monkeypatch.setattr(gateway_main, "gateway", h.gateway)
    agent = h.add_agent(INVOICES_READ)
    await h.call(h.token(agent), params=tool("delete_invoice"))
    auth = {"Authorization": f"Bearer {SERVICE_TOKEN}"}
    async with AsyncClient(transport=ASGITransport(app=gateway_main.app), base_url="http://test") as client:
        metrics = await client.get("/metrics", headers=auth)
        wrong = await client.get("/metrics", headers={"Authorization": "Bearer nope"})
    assert metrics.status_code == 200
    assert 'outcome="deny",reason="out_of_scope"' in metrics.text
    assert wrong.status_code == 401


@pytest.mark.asyncio
async def test_the_gateway_keeps_no_audit_ledger_of_its_own() -> None:
    """ADR 0030: the Black Box in core is the one audit trail. The gateway's old local ledger routes are gone (404, not merely guarded),
    even for a caller that holds the service token."""
    auth = {"Authorization": f"Bearer {SERVICE_TOKEN}"}
    async with AsyncClient(transport=ASGITransport(app=gateway_main.app), base_url="http://test") as client:
        gone = [await client.get(p, headers=auth) for p in ("/v1/audit/logs", "/v1/audit/verify", "/v1/audit")]
    assert [r.status_code for r in gone] == [404, 404, 404]
    assert not hasattr(gateway_main, "audit_logger")


# ---------------------------------------------------------------------------
# Safe Mode (Phase 2, M2): only tools declared 'read' are allowed
# ---------------------------------------------------------------------------

MIXED_SCOPES = [
    {"server": "xero", "tool": "list_invoices", "access": "read"},
    {"server": "xero", "tool": "delete_invoice", "access": "write"},
]


@pytest.mark.asyncio
async def test_safe_mode_allows_read_and_refuses_write() -> None:
    h = Harness()
    agent = h.add_agent(MIXED_SCOPES, safe_mode=True)
    token = h.token(agent)

    allowed = await h.call(token, params=tool("list_invoices"))
    assert "result" in allowed.body

    refused = await h.call(token, params=tool("delete_invoice", id="INV-1"))
    assert refused.status_code == 200
    assert refused.body["error"]["code"] == JSONRPC_POLICY_VIOLATION
    assert "Safe Mode is on" in refused.body["error"]["message"]
    assert [m["params"]["name"] for m in h.upstream.received if m["method"] == "tools/call"] == ["list_invoices"]
    record = h.decisions(1)[-1]
    assert record["decision"] == "BLOCK" and record["tool_name"] == "delete_invoice"
    assert "not declared read-only" in record["reasons"][0]


@pytest.mark.asyncio
async def test_without_safe_mode_the_same_agent_can_write() -> None:
    h = Harness()
    agent = h.add_agent(MIXED_SCOPES, safe_mode=False)
    assert "result" in (await h.call(h.token(agent), params=tool("delete_invoice", id="INV-1"))).body


@pytest.mark.asyncio
async def test_safe_mode_wildcards() -> None:
    h = Harness()
    wildcard_write = h.add_agent([{"server": "xero", "tool": "*", "access": "write"}], safe_mode=True)
    wildcard_read = h.add_agent([{"server": "xero", "tool": "*", "access": "read"}], safe_mode=True)
    assert (await h.call(h.token(wildcard_write), params=tool("list_invoices"))).body["error"]["code"] == JSONRPC_POLICY_VIOLATION
    assert "result" in (await h.call(h.token(wildcard_read), params=tool("list_invoices"))).body


@pytest.mark.asyncio
async def test_safe_mode_a_read_scope_wins_when_a_tool_has_both() -> None:
    h = Harness()
    both = [
        {"server": "xero", "tool": "list_invoices", "access": "write"},
        {"server": "xero", "tool": "*", "access": "read"},
    ]
    agent = h.add_agent(both, safe_mode=True)
    assert "result" in (await h.call(h.token(agent), params=tool("list_invoices"))).body


@pytest.mark.asyncio
async def test_safe_mode_keeps_reporting_plain_out_of_scope_for_uncovered_tools() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, safe_mode=True)
    resp = await h.call(h.token(agent), params=tool("execute_sql", query="select 1"))
    assert "out of scope" in resp.body["error"]["message"]
    assert "not in this agent's passport scopes" in h.decisions(1)[0]["reasons"][0]


@pytest.mark.asyncio
async def test_safe_mode_filters_tools_list() -> None:
    h = Harness()
    normal = h.add_agent(MIXED_SCOPES, safe_mode=False)
    safe = h.add_agent(MIXED_SCOPES, safe_mode=True)
    names = lambda resp: sorted(t["name"] for t in resp.body["result"]["tools"])  # noqa: E731
    assert names(await h.call(h.token(normal), method="tools/list")) == ["delete_invoice", "list_invoices"]
    assert names(await h.call(h.token(safe), method="tools/list")) == ["list_invoices"]


@pytest.mark.asyncio
async def test_safe_mode_still_applies_guardrails_to_read_tools() -> None:
    h = Harness()
    agent = h.add_agent([{"server": "xero", "tool": "execute_sql", "access": "read"}], safe_mode=True)
    resp = await h.call(h.token(agent), params=tool("execute_sql", query="DROP TABLE invoices;"))
    assert resp.body["error"]["code"] == JSONRPC_POLICY_VIOLATION
    assert h.upstream.received == []


@pytest.mark.asyncio
async def test_turning_safe_mode_on_reaches_the_gateway_within_the_slo() -> None:
    """A write that works now stops working once the cache window (<= 2 s) has passed."""
    h = Harness(ttl=2.0)
    agent = h.add_agent(MIXED_SCOPES, safe_mode=False)
    token = h.token(agent)
    assert "result" in (await h.call(token, params=tool("delete_invoice", id="1"))).body

    h.core.agents[str(agent)]["safe_mode"] = True  # an operator turns it on in core
    h.clock.now += 2.01
    refused = await h.call(token, params=tool("delete_invoice", id="2"))
    assert refused.body["error"]["code"] == JSONRPC_POLICY_VIOLATION
    assert "Safe Mode is on" in refused.body["error"]["message"]
    assert h.gateway.contexts._ttl <= 4.0 <= 5.0


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["missing", "true", "false", 1, 0, None])
async def test_a_missing_or_non_boolean_safe_mode_flag_denies(bad: Any) -> None:
    """Fail closed: a core that does not send a real boolean makes the gateway deny everything."""
    h = Harness()
    agent = h.add_agent(MIXED_SCOPES)
    if bad == "missing":
        del h.core.agents[str(agent)]["safe_mode"]
    else:
        h.core.agents[str(agent)]["safe_mode"] = bad
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert resp.status_code == 503
    assert resp.body["error"]["code"] == JSONRPC_GATEWAY_UNAVAILABLE
    assert h.upstream.received == []
