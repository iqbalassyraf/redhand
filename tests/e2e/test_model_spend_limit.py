"""
B5c on real processes (ADR 0025): a core, a gateway with the model proxy ON, and a fake provider, all on loopback. An agent calls the proxy until its measured spend crosses a small daily
dollar limit, and is then refused; the figure travels gateway -> core (batched report) -> core's priced measured spend -> the gateway's passport lookup -> the proxy's refusal.
Nothing real is called and no key is used. The fake provider reports 25 input and 10 output tokens a call, which the price table prices at 150 micro-dollars at the standard Sonnet rate.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


drill = _load("revocation_drill", "scripts/revocation_drill.py")
bench = _load("benchmark_model_proxy", "scripts/benchmark_model_proxy.py")

SONNET = "claude-sonnet-5-5"
BODY = {"model": SONNET, "max_tokens": 50, "messages": [{"role": "user", "content": "hi"}]}
CALL_MICRO_USD = 150  # 25 input tokens at $2 per million plus 10 output tokens at $10 per million
LIMIT_MICRO_USD = 400  # the third call brings measured spend to 450, over the limit


@pytest.fixture(scope="module")
def stack() -> Any:
    s = bench.Bench()
    s.gateway_env = {
        "AGENTWALL_MODEL_PROXY_ENABLED": "true", "AGENTWALL_MODEL_PROXY_ANTHROPIC_KEY": "fake-provider-key-for-the-e2e-test",
        "AGENTWALL_MODEL_PROXY_ANTHROPIC_URL": f"http://127.0.0.1:{s.provider_port}",
        "AGENTWALL_MODEL_USAGE_FLUSH_INTERVAL_SECONDS": "0.5", "AGENTWALL_CONTEXT_CACHE_TTL_SECONDS": "0.5",
    }
    try:
        s.start("provider")
        s.start("core")
        s.wait_healthy(f"{s.core}/health")
        s.wait_healthy(f"http://127.0.0.1:{s.provider_port}/health")
        s.start("gateway")
        s.wait_healthy(f"{s.gateway}/health")
        yield s
    finally:
        s.down()


def post(stack: Any, token: str, body: dict[str, Any] | None = None) -> httpx.Response:
    return httpx.post(f"{stack.gateway}/v1/model/anthropic/v1/messages", json=body or BODY, headers={"Authorization": f"Bearer {token}"}, timeout=10.0)


def measured_micro(op: Any, agent_id: str) -> int:
    rows = httpx.get(f"{op.stack.core}/v1/spend/agents", headers=op.headers, timeout=10.0).json()["agents"]
    measured = next(r for r in rows if r["agent_id"] == agent_id)["measured"]
    return int(measured["estimated_micro_usd"]) if measured else 0


def wait_for(predicate: Any, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


def test_an_agent_is_refused_after_its_measured_spend_crosses_the_daily_limit_and_allowed_again_when_it_is_raised(stack: Any) -> None:
    op = drill.Operator(stack)
    created = op.post("/v1/passports", {"name": "spend-limit-e2e", "framework": "custom", "scopes": [{"server": "model", "tool": "*"}]}).json()
    agent_id, key = str(created["passport"]["id"]), str(created["agent_key"])
    caller = drill.Caller(stack, key)
    assert caller.exchange() == 200
    limit = httpx.put(f"{stack.core}/v1/passports/{agent_id}/spend-limit", json={"spend_limit_micro_usd": LIMIT_MICRO_USD}, headers=op.headers, timeout=10.0)
    assert limit.status_code == 200, limit.text

    first = post(stack, caller.token)
    assert first.status_code == 200, first.text
    assert wait_for(lambda: measured_micro(op, agent_id) >= CALL_MICRO_USD, 10), "the proxy's usage never reached core's measured spend"

    statuses = [first.status_code]
    started = time.monotonic()
    while time.monotonic() - started < 20 and statuses[-1] != 429:
        time.sleep(0.2)
        statuses.append(post(stack, caller.token).status_code)
    assert statuses[-1] == 429, f"never refused: {statuses}"
    assert statuses[:-1] == [200] * (len(statuses) - 1) and len(statuses) >= 4, f"a refusal before the third call finished would mean the limit was read wrong: {statuses}"
    # The bound is time, not a call count: a slower machine makes more calls in the same few seconds of lag (flush 0.5 s + core + cache 0.5 s here).
    assert time.monotonic() - started < 15, "the refusal came too late: the lag is a few seconds, not unbounded"
    refused = post(stack, caller.token)
    assert refused.status_code == 429 and "daily model spend limit" in refused.json()["error"]["message"]
    assert str(LIMIT_MICRO_USD) not in refused.text, "the refusal leaks no figure"
    assert measured_micro(op, agent_id) >= LIMIT_MICRO_USD

    raised = httpx.put(f"{stack.core}/v1/passports/{agent_id}/spend-limit", json={"spend_limit_micro_usd": 10_000_000, "confirm": True}, headers=op.headers, timeout=10.0)
    assert raised.status_code == 200, raised.text
    assert wait_for(lambda: post(stack, caller.token).status_code == 200, 10), "raising the limit did not let the agent call again"

    unpriced = post(stack, caller.token, {**BODY, "model": "mystery-model"})
    assert unpriced.status_code == 403 and "cannot be priced" in unpriced.json()["error"]["message"], "a limit is set, so a model with no price is refused"

    removed = httpx.put(f"{stack.core}/v1/passports/{agent_id}/spend-limit", json={"spend_limit_micro_usd": None, "confirm": True}, headers=op.headers, timeout=10.0)
    assert removed.status_code == 200, removed.text
    assert wait_for(lambda: post(stack, caller.token, {**BODY, "model": "mystery-model"}).status_code == 200, 10), "with no limit there is no check at all"
