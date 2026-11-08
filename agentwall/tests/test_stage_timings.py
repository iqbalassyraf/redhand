"""
Stage timings: where the time goes inside a call. Added because the gateway's total "overhead" had a slow tail and a total cannot
say which step causes it. Stages are fixed names in code, so labels can never carry data from a request.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
import time
from uuid import uuid4

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentwall.src.gateway.identity import AgentTokenVerifier
from agentwall.src.gateway.metrics import LATENCY_BUCKETS_MS, GatewayMetrics

from test_gateway import INVOICES_READ, ORG, Harness, tool

_SPEC = importlib.util.spec_from_file_location("latency_baseline_stage", Path(__file__).resolve().parents[2] / "scripts" / "latency_baseline.py")
assert _SPEC and _SPEC.loader
lb = importlib.util.module_from_spec(_SPEC)
sys.modules["latency_baseline_stage"] = lb
_SPEC.loader.exec_module(lb)


def stages_in(h: Harness) -> dict[str, int]:
    found: dict[str, int] = {}
    for line in h.metrics.render().splitlines():
        m = re.match(r'^redhand_gateway_stage_ms_count\{stage="([a-z_]+)"\} (\d+)$', line)
        if m:
            found[m.group(1)] = int(m.group(2))
    return found


def test_a_stage_histogram_is_rendered_with_cumulative_buckets() -> None:
    metrics = GatewayMetrics()
    for ms in (0.5, 3.0, 40.0, 700.0):
        metrics.record_stage("verify", ms)
    text = metrics.render()
    assert 'redhand_gateway_stage_ms_bucket{stage="verify",le="1"} 1' in text
    assert 'redhand_gateway_stage_ms_bucket{stage="verify",le="5"} 2' in text
    assert 'redhand_gateway_stage_ms_bucket{stage="verify",le="1000"} 4' in text
    assert 'redhand_gateway_stage_ms_bucket{stage="verify",le="+Inf"} 4' in text
    assert 'redhand_gateway_stage_ms_count{stage="verify"} 4' in text and len(LATENCY_BUCKETS_MS) == 9


async def test_an_allowed_call_records_each_stage() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    await h.call(token, params=tool("list_invoices"))
    first = stages_in(h)
    assert first["verify"] == 1 and first["context_miss"] == 1 and first["guardrails"] == 1 and first["budget"] == 1 and first["honeytoken_scan"] == 1
    await h.call(token, params=tool("list_invoices"))
    second = stages_in(h)
    assert second["context_hit"] == 1 and second["context_miss"] == 1 and second["verify"] == 2


async def test_a_denied_call_still_records_the_stages_it_reached() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    await h.call(h.token(agent), params=tool("delete_invoice"))  # out of scope: stops before the guardrails and the budget
    seen = stages_in(h)
    assert seen["verify"] == 1 and seen["context_miss"] == 1 and "budget" not in seen


async def test_a_background_refresh_is_timed_and_a_failed_one_is_counted_separately() -> None:
    h = Harness(ttl=2.0)
    agent = h.add_agent(INVOICES_READ)
    token = h.token(agent)
    await h.call(token, params=tool("list_invoices"))
    h.clock.now += 1.2
    await h.call(token, params=tool("list_invoices"))
    for task in list(h.gateway.contexts._refreshing.values()):
        await task
    assert stages_in(h).get("context_refresh") == 1
    h.clock.now += 1.1  # the refreshed entry is now over half its lifetime old, still inside it
    h.core.mode = "down"
    await h.call(token, params=tool("list_invoices"))
    for task in list(h.gateway.contexts._refreshing.values()):
        await task
    assert stages_in(h).get("context_refresh_failed") == 1


async def test_a_key_refresh_is_timed() -> None:
    private = Ed25519PrivateKey.generate()
    jwk = jwt.algorithms.OKPAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": "k1", "use": "sig", "alg": "EdDSA"})
    metrics = GatewayMetrics()
    verifier = AgentTokenVerifier(
        public_key_pem=None, jwks_url="http://core/jwks",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"keys": [jwk]}))),
    )
    verifier.attach_metrics(metrics)
    now = int(time.time())
    claims = {"iss": "redhand-core", "aud": "redhand-gateway", "sub": str(uuid4()), "org": str(ORG), "ver": 1, "jti": "j", "iat": now, "exp": now + 60}
    await verifier.verify(jwt.encode(claims, private, algorithm="EdDSA", headers={"kid": "k1"}))
    assert 'redhand_gateway_stage_ms_count{stage="jwks_refresh"} 1' in metrics.render()


async def test_timing_does_not_change_what_a_call_returns() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    response = await h.call(h.token(agent), params=tool("list_invoices"))
    assert response.status_code == 200 and response.body["result"]["content"][0]["text"] == "ran list_invoices"


def test_every_stage_label_is_a_fixed_lowercase_name() -> None:
    metrics = GatewayMetrics()
    for name in ("verify", "context_hit", "context_miss", "honeytoken_scan", "guardrails", "budget", "budget_flush_now", "jwks_refresh", "context_refresh", "context_refresh_failed"):
        metrics.record_stage(name, 1.0)
    labels = set(re.findall(r'stage="([^"]+)"', metrics.render()))
    assert labels and all(re.fullmatch(r"[a-z_]+", label) for label in labels)


# --- the measuring script ----------------------------------------------------------------------------------------------

def stage_text(stage: str, counts: list[int], total: float) -> str:
    lines = [f'redhand_gateway_stage_ms_bucket{{stage="{stage}",le="{b}"}} {c}' for b, c in zip(LATENCY_BUCKETS_MS, counts)]
    lines += [f'redhand_gateway_stage_ms_bucket{{stage="{stage}",le="+Inf"}} {counts[-1]}',
              f'redhand_gateway_stage_ms_sum{{stage="{stage}"}} {total}', f'redhand_gateway_stage_ms_count{{stage="{stage}"}} {counts[-1]}']
    return "\n".join(lines)


def test_the_script_reports_which_stage_the_slow_calls_were_in() -> None:
    before = lb.parse_stages(stage_text("context_miss", [0] * 9, 0.0) + "\n" + stage_text("budget", [5, 5, 5, 5, 5, 5, 5, 5, 5], 3.0))
    after = lb.parse_stages(
        stage_text("context_miss", [0, 0, 0, 0, 0, 0, 8, 10, 10], 1500.0) + "\n" + stage_text("budget", [105, 105, 105, 105, 105, 105, 105, 105, 105], 40.0)
    )
    summary = lb.summarise_stages(before, after)
    assert summary["context_miss"]["calls"] == 10 and summary["context_miss"]["p50_upper_ms"] == 100.0 and summary["context_miss"]["p99_upper_ms"] == 250.0
    assert summary["budget"]["calls"] == 100 and summary["budget"]["p99_upper_ms"] == 1.0


def test_an_older_gateway_without_stages_gives_an_empty_breakdown() -> None:
    assert lb.parse_stages("# nothing\nredhand_gateway_decisions_total 3") == {}
    assert lb.summarise_stages({}, {}) == {}


def test_a_stage_that_did_not_run_during_the_test_is_left_out() -> None:
    snap = lb.parse_stages(stage_text("jwks_refresh", [1] * 9, 4.0))
    assert lb.summarise_stages(snap, snap) == {}
