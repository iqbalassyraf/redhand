"""
Black Box Recorder in the gateway (Phase 3, M1c): the buffer's bounds and drop accounting, grouping
by organization for one batch per flush, the single-flush-task join (the Phase 2 budget race
pattern), backoff, shutdown flush, and that every decision path in McpGateway reaches the recorder.
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import httpx
import pytest

from agentwall.src.gateway.metrics import GatewayMetrics
from agentwall.src.gateway.recorder import EventRecorder, GatewayEvent, HttpEventReporter

from test_gateway import INVOICES_READ, Harness, tool

ORG = UUID("00000000-0000-0000-0000-000000000010")
OTHER_ORG = UUID("00000000-0000-0000-0000-0000000000f0")


def event(agent_id: UUID | None = None, org: UUID = ORG, decision: str = "ALLOW", **overrides: object) -> GatewayEvent:
    base: dict[str, object] = dict(
        agent_id=agent_id or uuid4(), organization_id=org, occurred_at="2026-11-05T00:00:00+00:00",
        server="xero", method="tools/call", tool_name="list_invoices", decision=decision,
    )
    base.update(overrides)
    return GatewayEvent(**base)  # type: ignore[arg-type]


class FakeReporter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, UUID, list[dict[str, object]]]] = []
        self.accept = True
        self.crash = False

    async def send(self, instance_id: str, batch_id: str, organization_id: UUID, items: list[dict[str, object]]) -> bool:
        if self.crash:
            raise RuntimeError("event reporter exploded")
        self.calls.append((instance_id, batch_id, organization_id, items))
        return self.accept


# ---------------------------------------------------------------------------
# The buffer's own rules
# ---------------------------------------------------------------------------


def test_recording_is_synchronous_and_bounded() -> None:
    reporter = FakeReporter()
    rec = EventRecorder(instance_id="gw-1", reporter=reporter, max_buffered=3)
    for _ in range(5):
        rec.record(event())
    assert rec.buffered_count == 3  # the newest two were dropped, not recorded


def test_dropped_events_are_counted_and_reported_as_a_gap() -> None:
    reporter = FakeReporter()
    rec = EventRecorder(instance_id="gw-1", reporter=reporter, max_buffered=2)
    agent = uuid4()
    for _ in range(4):
        rec.record(event(agent_id=agent))
    assert rec.buffered_count == 2

    assert asyncio.run(rec.flush()) is True
    items = reporter.calls[0][3]
    gap_items = [i for i in items if i["method"] == "recorder.gap"]
    assert len(gap_items) == 1
    assert "2 event(s) dropped" in gap_items[0]["reasons"][0]
    assert gap_items[0]["agent_id"] == str(agent)  # a real agent of the org, not a throwaway id
    assert rec.buffered_count == 0  # flushed and cleared


def test_events_are_grouped_into_one_batch_per_organization() -> None:
    reporter = FakeReporter()
    rec = EventRecorder(instance_id="gw-1", reporter=reporter)
    rec.record(event(org=ORG))
    rec.record(event(org=ORG))
    rec.record(event(org=OTHER_ORG))

    assert asyncio.run(rec.flush()) is True
    orgs_sent = {call[2] for call in reporter.calls}
    assert orgs_sent == {ORG, OTHER_ORG}
    sizes = {call[2]: len(call[3]) for call in reporter.calls}
    assert sizes[ORG] == 2 and sizes[OTHER_ORG] == 1


def test_a_failed_flush_keeps_the_events_for_the_next_attempt() -> None:
    reporter = FakeReporter()
    reporter.accept = False
    rec = EventRecorder(instance_id="gw-1", reporter=reporter)
    rec.record(event())
    assert asyncio.run(rec.flush()) is False
    assert rec.buffered_count == 1  # nothing was lost


def test_one_organization_failing_does_not_block_another() -> None:
    class PartialReporter(FakeReporter):
        async def send(self, instance_id: str, batch_id: str, organization_id: UUID, items: list[dict[str, object]]) -> bool:
            await super().send(instance_id, batch_id, organization_id, items)
            return organization_id == ORG

    reporter = PartialReporter()
    rec = EventRecorder(instance_id="gw-1", reporter=reporter)
    rec.record(event(org=ORG))
    rec.record(event(org=OTHER_ORG))
    assert asyncio.run(rec.flush()) is False  # overall failure is reported...
    assert rec.buffered_count == 1  # ...but only OTHER_ORG's event is still buffered


def test_a_crashing_reporter_never_raises_out_of_flush() -> None:
    reporter = FakeReporter()
    reporter.crash = True
    rec = EventRecorder(instance_id="gw-1", reporter=reporter)
    rec.record(event())
    assert asyncio.run(rec.flush()) is False
    assert rec.buffered_count == 1


def _reporter_answering(body: object, metrics: GatewayMetrics) -> HttpEventReporter:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=body))
    return HttpEventReporter(
        core_url="http://core", service_token="token", http_client=httpx.AsyncClient(transport=transport),
        metrics=metrics,
    )


def test_items_core_refuses_to_store_are_counted_not_hidden() -> None:
    """Regression: a database fault once made core reject every item while still answering 200, and
    nothing in the gateway showed it."""
    metrics = GatewayMetrics()
    reporter = _reporter_answering({"accepted": 1, "rejected": 2}, metrics)
    assert asyncio.run(reporter.send("gw-1", "b1", ORG, [{}])) is True  # acknowledged: never resent
    assert "redhand_gateway_events_rejected_total 2" in metrics.render()


def test_a_fully_accepted_batch_counts_no_rejections() -> None:
    metrics = GatewayMetrics()
    reporter = _reporter_answering({"accepted": 3, "rejected": 0}, metrics)
    assert asyncio.run(reporter.send("gw-1", "b1", ORG, [{}])) is True
    assert "redhand_gateway_events_rejected_total 0" in metrics.render()


def test_an_unreadable_acknowledgement_is_still_an_acknowledgement() -> None:
    metrics = GatewayMetrics()
    reporter = _reporter_answering({"unexpected": True}, metrics)
    assert asyncio.run(reporter.send("gw-1", "b1", ORG, [{}])) is True
    assert "redhand_gateway_events_rejected_total 0" in metrics.render()


def test_concurrent_flushes_join_the_one_in_flight() -> None:
    """Mirrors the Phase 2 budget race: two overlapping flush triggers must not send the buffer
    twice. A reporter that yields before returning exposes the race if the single-task guard is
    missing."""

    class SlowReporter(FakeReporter):
        async def send(self, instance_id: str, batch_id: str, organization_id: UUID, items: list[dict[str, object]]) -> bool:
            await asyncio.sleep(0.01)
            return await super().send(instance_id, batch_id, organization_id, items)

    async def run() -> None:
        reporter = SlowReporter()
        rec = EventRecorder(instance_id="gw-1", reporter=reporter)
        rec.record(event())
        t1 = rec._start_flush()
        t2 = rec._start_flush()
        assert t1 is t2  # the second caller joined the first task instead of starting a new one
        await t1

    asyncio.run(run())


def test_batches_are_capped_at_max_batch_size() -> None:
    reporter = FakeReporter()
    rec = EventRecorder(instance_id="gw-1", reporter=reporter, max_batch_size=2, max_buffered=10)
    for _ in range(2):
        rec.record(event())
    assert asyncio.run(rec.flush()) is True
    assert len(reporter.calls[0][3]) == 2


@pytest.mark.asyncio
async def test_stop_sends_a_final_flush() -> None:
    reporter = FakeReporter()
    rec = EventRecorder(instance_id="gw-1", reporter=reporter)
    rec.record(event())
    await rec.stop()
    assert len(reporter.calls) == 1
    assert rec.buffered_count == 0


# ---------------------------------------------------------------------------
# Every decision path in McpGateway reaches the recorder
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allowed_call_is_recorded_with_argument_digest_and_no_raw_arguments() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    tok = h.token(agent)
    await h.call(tok, params=tool("list_invoices", invoice_id="INV-1"))
    await h.recorder.flush()

    items = h.event_reporter.events
    assert len(items) == 1
    item = items[0]
    assert item["decision"] == "ALLOW"
    assert item["tool_name"] == "list_invoices"
    assert item["argument_keys"] == ["invoice_id"]
    assert "INV-1" not in str(item)  # the raw argument value never crosses this boundary
    assert len(item["arguments_sha256"]) == 64


@pytest.mark.asyncio
async def test_out_of_scope_refusal_is_recorded() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    tok = h.token(agent)
    await h.call(tok, params=tool("delete_invoice", invoice_id="INV-1"))
    await h.recorder.flush()

    item = h.event_reporter.events[0]
    assert item["decision"] == "BLOCK"
    assert item["reasons"]


@pytest.mark.asyncio
async def test_frozen_passport_refusal_is_recorded() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, status="frozen")
    tok = h.token(agent)
    await h.call(tok, params=tool("list_invoices"))
    await h.recorder.flush()

    item = h.event_reporter.events[0]
    assert item["decision"] == "BLOCK"
    assert item["reasons"] == ["passport_frozen"]


@pytest.mark.asyncio
async def test_upstream_failure_is_recorded_as_error() -> None:
    h = Harness()
    h.upstream.mode = "down"
    agent = h.add_agent(INVOICES_READ)
    tok = h.token(agent)
    await h.call(tok, params=tool("list_invoices"))
    await h.recorder.flush()

    item = h.event_reporter.events[0]
    assert item["decision"] == "ERROR"


@pytest.mark.asyncio
async def test_recorder_outage_never_blocks_enforcement() -> None:
    """Core's event endpoint being down must not change what the gateway allows or refuses."""
    h = Harness()
    h.event_reporter.crash = True
    agent = h.add_agent(INVOICES_READ)
    tok = h.token(agent)
    resp = await h.call(tok, params=tool("list_invoices"))
    assert resp.status_code == 200  # the call still went through
    await h.recorder.flush()
    assert h.recorder.buffered_count == 1  # the event is still waiting, not lost silently or crashed
