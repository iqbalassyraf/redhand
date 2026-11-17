"""
The model proxy's usage reporter (Phase 4.5 B5b): the proxy records what the PROVIDER counted into memory (never blocking a call), and a background flush sends it to core in
idempotent batches. A failed batch is retried with the SAME id; the queues are bounded and drop-and-count rather than block; nothing but counts and model names is ever sent.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from agentwall.src.gateway.model_proxy import ModelUsage
from agentwall.src.gateway.model_usage_reporter import MAX_ITEMS_PER_BATCH, ReportingUsageSink

ORG = uuid4()
A1, A2 = uuid4(), uuid4()


class Core:
    """A fake core: records every request, answers with the next scripted status."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.headers: list[httpx.Headers] = []
        self.urls: list[str] = []
        self.script: list[int | Exception] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        self.headers.append(request.headers)
        self.urls.append(str(request.url))
        step = self.script.pop(0) if self.script else 200
        if isinstance(step, Exception):
            raise step
        body = {"accepted": len(self.requests[-1]["items"]), "rejected": 0, "duplicate": False} if step == 200 else {"detail": "x"}
        return httpx.Response(step, json=body)


class Clock:
    now = 1000.0

    def __call__(self) -> float:
        return self.now


def make(core: Core, **kwargs: Any) -> tuple[ReportingUsageSink, Clock]:
    clock = Clock()
    client = httpx.AsyncClient(transport=httpx.MockTransport(core.handler))
    kwargs.setdefault("service_token", "internal-token-0123456789")
    sink = ReportingUsageSink(core_url="http://core.test", http_client=client, clock=clock, jitter=lambda: 1.0, **kwargs)
    return sink, clock


def usage(agent: UUID = A1, model: str = "claude-sonnet-5-5", inp: int = 100, out: int = 50, outcome: str = "ok", stream: bool = False) -> ModelUsage:
    return ModelUsage(agent, ORG, model, inp, out, stream, outcome)


# --- recording ----------------------------------------------------------------------------------------------------------------------

async def test_calls_of_one_agent_and_model_are_added_up() -> None:
    sink, _ = make(Core())
    for _ in range(3):
        sink.record(usage(inp=100, out=50))
    sink.record(usage(model="claude-haiku-5-5", inp=1, out=1))
    pending = sink.pending_snapshot()
    assert len(pending) == 2
    sonnet = next(p for p in pending if p["model"] == "claude-sonnet-5-5")
    assert sonnet["calls"] == 3 and sonnet["input_tokens"] == 300 and sonnet["output_tokens"] == 150 and sonnet["calls_without_usage"] == 0


async def test_a_call_with_no_provider_usage_is_counted_apart_not_as_free() -> None:
    sink, _ = make(Core())
    sink.record(usage(inp=0, out=0, outcome="usage_not_reported"))
    [item] = sink.pending_snapshot()
    assert item["calls"] == 1 and item["calls_without_usage"] == 1 and item["input_tokens"] == 0


@pytest.mark.parametrize("outcome", ["stream_interrupted", "stream_too_large", "stream_cancelled"])
async def test_an_interrupted_stream_counts_the_tokens_the_provider_had_reported_so_far(outcome: str) -> None:
    sink, _ = make(Core())
    sink.record(usage(inp=40, out=0, outcome=outcome, stream=True))
    [item] = sink.pending_snapshot()
    assert item["calls"] == 1 and item["input_tokens"] == 40 and item["calls_without_usage"] == 0


@pytest.mark.parametrize("outcome", ["provider_error", "unauthorized", "model_denied", "malformed", "something_new"])
async def test_a_call_that_used_nothing_is_not_reported(outcome: str) -> None:
    sink, _ = make(Core())
    sink.record(usage(inp=0, out=0, outcome=outcome))
    assert sink.pending_snapshot() == []


async def test_without_a_service_token_nothing_is_kept_or_sent() -> None:
    core = Core()
    sink, _ = make(core, service_token=None)
    sink.record(usage())
    assert sink.pending_snapshot() == [] and await sink.flush() is True and core.requests == []
    assert sink.stats["dropped_not_configured"] == 1


# --- what is sent -----------------------------------------------------------------------------------------------------------------

async def test_a_flush_posts_one_batch_with_the_service_token_and_counts_only() -> None:
    core = Core()
    sink, _ = make(core)
    sink.record(usage(inp=100, out=50, stream=True))
    assert await sink.flush() is True
    assert core.urls == ["http://core.test/internal/v1/model-usage"]
    assert core.headers[0]["authorization"] == "Bearer internal-token-0123456789"
    body = core.requests[0]
    UUID(body["batch_id"])
    [item] = body["items"]
    assert set(item) == {"agent_id", "provider", "model", "calls", "input_tokens", "output_tokens", "calls_without_usage", "occurred_at"}
    assert item["provider"] == "anthropic" and item["agent_id"] == str(A1) and "organization_id" not in json.dumps(body)
    assert sink.pending_snapshot() == []


async def test_a_large_flush_is_split_into_batches_of_at_most_the_limit() -> None:
    core = Core()
    sink, _ = make(core)
    for i in range(MAX_ITEMS_PER_BATCH * 2 + 5):
        sink.record(usage(model=f"m-{i}"))
    assert await sink.flush() is True
    sizes = [len(r["items"]) for r in core.requests]
    assert sizes == [MAX_ITEMS_PER_BATCH, MAX_ITEMS_PER_BATCH, 5]
    assert len({r["batch_id"] for r in core.requests}) == 3


async def test_nothing_is_sent_when_there_is_nothing_to_report() -> None:
    core = Core()
    sink, _ = make(core)
    assert await sink.flush() is True and core.requests == []


# --- failure: retried with the same id, never lost silently, never blocking ---------------------------------------------------------

@pytest.mark.parametrize("failure", [503, 500, 429, httpx.ConnectError("down"), httpx.ReadTimeout("slow")])
async def test_a_failed_batch_is_retried_with_the_same_id_and_the_same_items(failure: int | Exception) -> None:
    core = Core()
    core.script = [failure]
    sink, clock = make(core)
    sink.record(usage(inp=7, out=3))
    assert await sink.flush() is False
    first = core.requests[0]
    clock.now += 600
    assert await sink.flush() is True
    assert core.requests[1]["batch_id"] == first["batch_id"] and core.requests[1]["items"] == first["items"]
    assert sink.stats["reported_batches"] == 1 and sink.stats["failed_batches"] == 1


async def test_usage_recorded_while_a_batch_waits_goes_in_a_new_batch() -> None:
    core = Core()
    core.script = [503]
    sink, clock = make(core)
    sink.record(usage(inp=1, out=1))
    await sink.flush()
    sink.record(usage(inp=2, out=2))
    clock.now += 600
    assert await sink.flush() is True
    ids = [r["batch_id"] for r in core.requests]
    assert ids[0] == ids[1] and ids[2] != ids[0]
    assert sum(i["calls"] for r in core.requests[1:] for i in r["items"]) == 2


async def test_a_flush_that_failed_waits_before_the_next_one_and_the_wait_is_capped() -> None:
    core = Core()
    core.script = [503] * 40
    sink, clock = make(core)
    sink.record(usage())
    for _ in range(30):
        await sink.flush()
        clock.now += 1
    assert 0 < sink.next_flush_delay() <= 60.0 * 1.0001
    sent = len(core.requests)
    await sink.flush_if_due()
    assert len(core.requests) == sent, "inside the wait nothing is sent"
    clock.now += 120
    await sink.flush_if_due()
    assert len(core.requests) == sent + 1, "after the wait the next attempt is made"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
async def test_a_batch_core_refuses_for_good_is_dropped_and_counted_not_retried_forever(status: int) -> None:
    core = Core()
    core.script = [status]
    sink, clock = make(core)
    sink.record(usage())
    await sink.flush()
    clock.now += 600
    await sink.flush()
    assert len(core.requests) == 1 and sink.stats["dropped_refused"] == 1


async def test_core_saying_duplicate_clears_the_batch() -> None:
    core = Core()
    sink, _ = make(core)
    sink.record(usage())
    assert await sink.flush() is True and sink.stats["reported_batches"] == 1


async def test_the_memory_is_bounded_and_overflow_is_counted_not_raised() -> None:
    sink, _ = make(Core(), max_keys=5)
    for i in range(20):
        sink.record(usage(model=f"m-{i}"))
    assert len(sink.pending_snapshot()) == 5 and sink.stats["dropped_overflow"] == 15
    sink.record(usage(model="m-0", inp=1, out=1))
    assert next(p for p in sink.pending_snapshot() if p["model"] == "m-0")["calls"] == 2, "a known key still adds up when full"


async def test_during_a_long_outage_usage_coalesces_in_memory_and_stays_bounded() -> None:
    core = Core()
    core.script = [503] * 1000
    sink, clock = make(core, max_keys=4)
    for round_ in range(50):
        for i in range(10):
            sink.record(usage(model=f"m-{i % 6}", inp=1, out=1))
        await sink.flush()
        clock.now += 600
    assert len(sink.pending_snapshot()) <= 4 and sink.retry_depth() <= 1
    assert sink.stats["dropped_overflow"] > 0


async def test_record_never_raises_even_for_hostile_values() -> None:
    sink, _ = make(Core())
    sink.record(usage(model="x" * 10_000, inp=10**30, out=-5))
    sink.record(usage(model="", inp=1, out=1))
    for item in sink.pending_snapshot():
        assert len(item["model"]) <= 128 and 0 <= item["input_tokens"] <= 10**12 and 0 <= item["output_tokens"] <= 10**12 and item["model"]


async def test_the_reporter_never_leaks_the_service_token_in_its_logs_or_stats(caplog: pytest.LogCaptureFixture) -> None:
    core = Core()
    core.script = [503]
    sink, _ = make(core)
    sink.record(usage())
    await sink.flush()
    assert "internal-token-0123456789" not in caplog.text and "internal-token-0123456789" not in json.dumps(sink.stats)


async def test_metrics_lines_are_prometheus_counters() -> None:
    sink, _ = make(Core())
    sink.record(usage())
    await sink.flush()
    text = sink.render_prometheus()
    assert "agentwall_model_usage_reported_batches_total 1" in text and "agentwall_model_usage_dropped_total" in text


# --- wiring: the gateway picks the reporting sink only when the proxy is on ------------------------------------------------------------

@pytest.mark.parametrize(("enabled", "expected"), [("true", "ReportingUsageSink"), ("false", "MemoryUsageSink")])
def test_the_gateway_reports_usage_only_when_the_proxy_is_on(enabled: str, expected: str) -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "AGENTWALL_ENVIRONMENT": "staging", "AGENTWALL_MODEL_PROXY_ENABLED": enabled, "AGENTWALL_CORE_SERVICE_TOKEN": "t" * 32}
    out = subprocess.run([sys.executable, "-c", "from agentwall.src.main import model_proxy; print(type(model_proxy.sink).__name__)"], cwd=root, env=env, capture_output=True, text=True, timeout=60, check=True)
    assert out.stdout.strip().splitlines()[-1] == expected
