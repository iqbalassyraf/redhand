"""
Phase 1 "done" tests (CLAUDE.md §19), end to end.

Real components, wired in-process over ASGI (no network):
  operator --HTTP--> redhand-core (local store)
  agent    --HTTP--> AgentWall gateway --> redhand-core (/jwks, /internal context)
                                       --> demo MCP server (examples/demo_mcp_server.py)

1. Register an agent -> passport visible with owner, scopes, expiry.
2. Agent connected via gateway -> in-scope call succeeds; out-of-scope denied and logged.
3. Revoke one agent -> its next call fails within the revocation SLO (5 s).
4. Freeze all -> every agent in the tenant is denied; the audit log records it.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
from pydantic import SecretStr
import pytest

from agentwall.src import main as gateway_main
from agentwall.src.firewall.engine import FirewallPolicyEngine
from agentwall.src.gateway.budget import BudgetMeter, HttpUsageReporter
from agentwall.src.gateway.context import CoreContextClient
from agentwall.src.gateway.identity import AgentTokenVerifier
from agentwall.src.gateway.metrics import GatewayMetrics
from agentwall.src.gateway.recorder import EventRecorder, HttpEventReporter
from agentwall.src.gateway.pins import HttpPinReporter, PinCoordinator
from agentwall.src.gateway.radar_scan import HttpFindingsReporter, HttpScanCountsReporter, RadarScanner
from agentwall.src.gateway.trips import HttpTripReporter, TripDispatcher
from agentwall.src.gateway.service import McpGateway
from agentwall.src.gateway.upstream import UpstreamForwarder
from examples import demo_mcp_server
from redhand_core.auth.operator import issue_operator_token
from redhand_core.config import Settings, get_settings
from redhand_core.main import create_app
from redhand_core.routers import agent_auth
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS, LocalSupabaseAdapter

SERVICE_TOKEN = "e2e-internal-service-token-0123456789"
REVOCATION_SLO_SECONDS = 5.0
POLICY_FILE = Path(__file__).resolve().parents[2] / "agentwall" / "config" / "policies.yaml"


class Stack:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, context_ttl: float = 2.0) -> None:
        self.settings = Settings(
            ENVIRONMENT="test",
            OPERATOR_JWT_SECRET=SecretStr("e2e-operator-secret-0123456789abcdef0123456789"),
            INTERNAL_SERVICE_TOKEN=SecretStr(SERVICE_TOKEN),
            ALLOW_INSECURE_MCP_URLS=True,
        )
        self.store = LocalSupabaseAdapter()
        core_app = create_app(self.settings)
        self.core_app = core_app
        core_app.dependency_overrides[get_settings] = lambda: self.settings
        core_app.dependency_overrides[get_supabase_service_client] = lambda: self.store
        agent_auth._exchange_limiter._events.clear()
        self.core = httpx.AsyncClient(transport=httpx.ASGITransport(app=core_app), base_url="http://core")

        demo_mcp_server.calls.clear()
        self.gateway = McpGateway(
            verifier=AgentTokenVerifier(
                public_key_pem=None, jwks_url="http://core/v1/agent-auth/jwks", http_client=self.core
            ),
            contexts=CoreContextClient(
                core_url="http://core", service_token=SERVICE_TOKEN, ttl_seconds=context_ttl,
                instance_id="e2e-gateway-0001", http_client=self.core,
            ),
            forwarder=UpstreamForwarder(
                allow_insecure=True,
                max_response_bytes=1_000_000,
                connect_timeout=2,
                total_timeout=5,
                http_client=httpx.AsyncClient(transport=httpx.ASGITransport(app=demo_mcp_server.app)),
            ),
            firewall=FirewallPolicyEngine(POLICY_FILE),
            metrics=GatewayMetrics(),
            budget=BudgetMeter(
                instance_id="e2e-gateway-0001",
                reporter=HttpUsageReporter(core_url="http://core", service_token=SERVICE_TOKEN, http_client=self.core),
            ),
            recorder=EventRecorder(
                instance_id="e2e-gateway-0001",
                reporter=HttpEventReporter(core_url="http://core", service_token=SERVICE_TOKEN, http_client=self.core),
            ),
            trips=TripDispatcher(
                reporter=HttpTripReporter(core_url="http://core", service_token=SERVICE_TOKEN, http_client=self.core),
                retry_delays=(),
            ),
            pins=PinCoordinator(
                reporter=HttpPinReporter(core_url="http://core", service_token=SERVICE_TOKEN, http_client=self.core), retry_delays=(),
            ),
            radar=RadarScanner(
                reporter=HttpFindingsReporter(core_url="http://core", service_token=SERVICE_TOKEN, http_client=self.core), retry_delays=(),
                counts_reporter=HttpScanCountsReporter(core_url="http://core", service_token=SERVICE_TOKEN, http_client=self.core),
            ),
        )
        monkeypatch.setattr(gateway_main, "gateway", self.gateway)
        self.edge = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway_main.app), base_url="http://gateway")

    def operator(self, user: str) -> dict[str, str]:
        token = issue_operator_token(user_id=UUID(DEV_OPERATORS[user]["id"]), email=None, settings=self.settings)
        return {"Authorization": f"Bearer {token}"}

    async def register_server(self) -> None:
        resp = await self.core.post(
            "/v1/mcp-servers",
            json={"slug": "xero", "name": "Demo invoices", "url": "http://demo/mcp"},
            headers=self.operator("admin"),
        )
        assert resp.status_code == 201, resp.text

    async def register_agent(self, name: str, scopes: list[dict[str, str]]) -> dict[str, Any]:
        resp = await self.core.post(
            "/v1/passports",
            json={"name": name, "framework": "n8n", "scopes": scopes, "expires_in_days": 30},
            headers=self.operator("admin"),  # registering an agent issues its key: admin (D1, owner decision 2026-11-17)
        )
        assert resp.status_code == 201, resp.text
        return resp.json()

    async def agent_token(self, agent_key: str) -> str:
        resp = await self.core.post("/v1/agent-auth/token", headers={"Authorization": f"Bearer {agent_key}"})
        assert resp.status_code == 200, resp.text
        return resp.json()["access_token"]

    async def blackbox_events(self) -> list[dict[str, Any]]:
        """What the gateway reported to the Black Box (the one audit trail), oldest first, after flushing the recorder."""
        await self.gateway.recorder.flush()
        return sorted((e for e in self.store.tables.get("agent_events", []) if str(e["organization_id"]) == str(DEFAULT_ORG_ID)), key=lambda e: e["seq"])

    async def call_tool(self, token: str, tool: str, **args: Any) -> httpx.Response:
        return await self.edge.post(
            "/mcp/xero",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}},
            headers={"Authorization": f"Bearer {token}"},
        )

    async def close(self) -> None:
        await self.edge.aclose()
        await self.core.aclose()


async def _wait_until_denied(stack: Stack, token: str) -> float:
    """Calls the gateway until it denies; returns seconds elapsed. Fails after the SLO."""
    start = time.monotonic()
    while True:
        resp = await stack.call_tool(token, "list_invoices")
        if resp.status_code == 403:
            return time.monotonic() - start
        assert "result" in resp.json(), resp.text
        if time.monotonic() - start > REVOCATION_SLO_SECONDS:
            pytest.fail("Revocation did not take effect within the SLO")
        await asyncio.sleep(0.1)


INVOICE_READER = [{"server": "xero", "tool": "list_invoices", "access": "read"}]


@pytest.mark.asyncio
async def test_done_1_register_agent_passport_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    stack = Stack(monkeypatch)
    await stack.register_server()
    created = await stack.register_agent("Invoice bot", INVOICE_READER)
    listed = (await stack.core.get("/v1/passports", headers=stack.operator("viewer"))).json()
    passport = next(p for p in listed if p["id"] == created["passport"]["id"])
    assert passport["owner_id"] == DEV_OPERATORS["admin"]["id"]
    assert passport["scopes"] == INVOICE_READER
    assert passport["expires_at"] and passport["status"] == "active"
    await stack.close()


@pytest.mark.asyncio
async def test_done_2_in_scope_allowed_out_of_scope_denied_and_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    stack = Stack(monkeypatch)
    await stack.register_server()
    created = await stack.register_agent("Invoice bot", INVOICE_READER)
    token = await stack.agent_token(created["agent_key"])

    allowed = await stack.call_tool(token, "list_invoices", month="2026-10")
    assert allowed.status_code == 200
    assert allowed.json()["result"]["content"][0]["text"] == "demo: list_invoices executed"

    denied = await stack.call_tool(token, "delete_invoice", invoice_id="INV-9")
    assert denied.json()["error"]["code"] == -32000
    executed = [c["params"]["name"] for c in demo_mcp_server.calls if c["method"] == "tools/call"]
    assert executed == ["list_invoices"]  # the out-of-scope call never reached the server

    records = [e for e in await stack.blackbox_events() if e["method"] == "tools/call"]
    assert [(r["tool_name"], r["decision"]) for r in records] == [
        ("list_invoices", "ALLOW"),
        ("delete_invoice", "BLOCK"),
    ]
    assert all(str(r["organization_id"]) == str(DEFAULT_ORG_ID) for r in records)

    listed = await stack.edge.post(
        "/mcp/xero", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert [t["name"] for t in listed.json()["result"]["tools"]] == ["list_invoices"]
    await stack.close()


@pytest.mark.asyncio
async def test_done_3_revoke_one_agent_fails_within_slo(monkeypatch: pytest.MonkeyPatch) -> None:
    stack = Stack(monkeypatch)
    await stack.register_server()
    target = await stack.register_agent("Target", INVOICE_READER)
    bystander = await stack.register_agent("Bystander", INVOICE_READER)
    target_token = await stack.agent_token(target["agent_key"])
    bystander_token = await stack.agent_token(bystander["agent_key"])
    assert (await stack.call_tool(target_token, "list_invoices")).status_code == 200

    resp = await stack.core.post(
        f"/v1/passports/{target['passport']['id']}/revoke",
        json={"confirm": True, "reason": "e2e"},
        headers=stack.operator("admin"),
    )
    assert resp.status_code == 200
    elapsed = await _wait_until_denied(stack, target_token)
    assert elapsed <= REVOCATION_SLO_SECONDS

    # The still-unexpired access token is useless, the agent key no longer exchanges,
    # and other agents are unaffected.
    assert (await stack.call_tool(target_token, "list_invoices")).json()["error"]["data"]["passport_status"] == "revoked"
    exchange = await stack.core.post(
        "/v1/agent-auth/token", headers={"Authorization": f"Bearer {target['agent_key']}"}
    )
    assert exchange.status_code == 401
    assert (await stack.call_tool(bystander_token, "list_invoices")).status_code == 200
    await stack.close()


@pytest.mark.asyncio
async def test_done_4_freeze_all_denies_every_agent_and_is_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    stack = Stack(monkeypatch)
    await stack.register_server()
    agents = [await stack.register_agent(f"Bot {i}", INVOICE_READER) for i in range(3)]
    tokens = [await stack.agent_token(a["agent_key"]) for a in agents]
    for token in tokens:
        assert (await stack.call_tool(token, "list_invoices")).status_code == 200

    resp = await stack.core.post(
        "/v1/passports/freeze-all",
        json={"confirm": True, "reason": "suspicious invoices"},
        headers=stack.operator("owner"),
    )
    assert resp.status_code == 200
    for token in tokens:
        assert await _wait_until_denied(stack, token) <= REVOCATION_SLO_SECONDS

    audit = (await stack.core.get("/v1/audit/control", headers=stack.operator("viewer"))).json()
    entry = next(e for e in audit if e["action"] == "organization.frozen_all")
    assert entry["actor_user_id"] == DEV_OPERATORS["owner"]["id"]
    assert entry["reason"] == "suspicious invoices"
    assert {a["passport"]["id"] for a in agents} <= set(entry["details"]["frozen_agent_ids"])

    for a in agents:
        refused = await stack.core.post(
            "/v1/agent-auth/token", headers={"Authorization": f"Bearer {a['agent_key']}"}
        )
        assert refused.status_code == 403
    await stack.close()
