"""
Gateway overhead benchmark (CLAUDE.md §8 budget: p50 <= 10 ms, p99 <= 50 ms, excluding
upstream tool time).

Runs the real gateway code (token verification, passport context lookup, scope check,
guardrails, forwarding, response filtering and audit) in-process, with redhand-core and
the MCP server replaced by instant in-memory responders. It therefore measures RedHand's
own CPU cost per call, not network latency between machines.

Two cases:
  warm  - passport context served from the 2 s cache (the common case)
  cold  - every call fetches the context from "core" (worst case, cache disabled)

Also measures how long a revocation takes to reach the gateway with the default 2 s cache.

Usage (from the repository root): PYTHONPATH=. uv run python scripts/benchmark_gateway.py [calls]
"""

from __future__ import annotations

import asyncio
import statistics
import sys
import time
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import jwt

from agentwall.src.firewall.engine import FirewallPolicyEngine
from agentwall.src.gateway.budget import BudgetMeter
from agentwall.src.gateway.context import CoreContextClient
from agentwall.src.gateway.identity import AgentTokenVerifier
from agentwall.src.gateway.metrics import GatewayMetrics
from agentwall.src.gateway.service import McpGateway
from agentwall.src.gateway.upstream import UpstreamForwarder
from agentwall.src.telemetry.audit_logger import TamperEvidentAuditLogger

ORG = str(uuid4())
AGENT = str(uuid4())
STATE = {"status": "active"}


def core_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "agent": {
                "id": AGENT, "organization_id": ORG, "status": STATE["status"], "version": 1,
                "scopes": [{"server": "xero", "tool": "list_invoices", "access": "read"}],
                "expires_at": "2099-01-01T00:00:00+00:00",
                "safe_mode": False,
                "budget": {
                    "daily_call_limit": None, "used_by_other_instances": 0, "day_key": "2026-11-04",
                    "resets_at": "2026-11-04T16:00:00+00:00", "action": "deny",
                },
            },
            "server": {"slug": "xero", "url": "https://mcp.example.com/x"},
        },
    )


def upstream_handler(request: httpx.Request) -> httpx.Response:
    import json

    msg = json.loads(request.content)
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": "ok"}]}})


class _NullReporter:
    """Reports go nowhere: this benchmark measures the gateway's own cost, not the network to core."""

    async def send(self, instance_id: str, items: list[dict[str, Any]]) -> bool:
        return True


def build(ttl: float) -> tuple[McpGateway, str]:
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    now = int(time.time())
    token = jwt.encode(
        {"iss": "redhand-core", "aud": "redhand-gateway", "sub": AGENT, "org": ORG, "ver": 1,
         "jti": "b", "iat": now, "exp": now + 3600},
        key, algorithm="EdDSA",
    )
    gateway = McpGateway(
        verifier=AgentTokenVerifier(public_key_pem=pem, jwks_url=None),
        contexts=CoreContextClient(
            core_url="http://core", service_token="t", ttl_seconds=ttl, instance_id="benchmark-gateway-0001",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(core_handler)),
        ),
        forwarder=UpstreamForwarder(
            allow_insecure=True, max_response_bytes=1_000_000, connect_timeout=1, total_timeout=5,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler)),
        ),
        firewall=FirewallPolicyEngine("agentwall/config/policies.yaml"),
        audit_logger=TamperEvidentAuditLogger(),
        metrics=GatewayMetrics(),
        budget=BudgetMeter(instance_id="benchmark-gateway-0001", reporter=_NullReporter()),
    )
    return gateway, token


async def run_case(name: str, ttl: float, calls: int) -> dict[str, float]:
    gateway, token = build(ttl)
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "list_invoices", "arguments": {"month": "2026-10"}}}
    for _ in range(50):  # warm-up
        await gateway.handle(server="xero", message=message, bearer_token=token, client_headers={}, upstream_authorization=None)
    samples: list[float] = []
    for _ in range(calls):
        start = time.perf_counter()
        resp = await gateway.handle(server="xero", message=message, bearer_token=token, client_headers={}, upstream_authorization=None)
        samples.append((time.perf_counter() - start) * 1000)
        assert resp.status_code == 200
    samples.sort()
    result = {
        "p50": statistics.median(samples),
        "p99": samples[int(len(samples) * 0.99) - 1],
        "max": samples[-1],
    }
    print(f"{name:<5} calls={calls}  p50={result['p50']:.3f} ms  p99={result['p99']:.3f} ms  max={result['max']:.3f} ms")
    return result


async def revocation_delay() -> float:
    gateway, token = build(2.0)
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_invoices", "arguments": {}}}
    STATE["status"] = "active"
    await gateway.handle(server="xero", message=message, bearer_token=token, client_headers={}, upstream_authorization=None)
    STATE["status"] = "revoked"
    start = time.monotonic()
    while True:
        resp = await gateway.handle(server="xero", message=message, bearer_token=token, client_headers={}, upstream_authorization=None)
        if resp.status_code == 403:
            STATE["status"] = "active"
            return time.monotonic() - start
        await asyncio.sleep(0.05)


async def main() -> None:
    calls = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    warm = await run_case("warm", 2.0, calls)
    cold = await run_case("cold", 0.0, calls)
    delay = await revocation_delay()
    print(f"revocation reached gateway after {delay:.2f} s (budget 5 s)")
    ok = warm["p50"] <= 10 and warm["p99"] <= 50 and delay <= 5
    print("within budget" if ok else "OVER BUDGET")
    _ = cold


if __name__ == "__main__":
    asyncio.run(main())
