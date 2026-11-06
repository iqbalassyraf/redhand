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


# ---------------------------------------------------------------------------
# Payload capture through the gateway (Phase 3 M2b)
# ---------------------------------------------------------------------------

EMAIL = "ali.bin.abu@example.com.my"
LEAKY = [{"server": "xero", "tool": "leaky", "access": "read"}]


async def _flushed(h: Harness) -> list[dict[str, object]]:
    await h.recorder.flush()
    return h.event_reporter.events


@pytest.mark.asyncio
async def test_no_payload_is_built_while_capture_is_off() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)  # payload_capture defaults to False
    await h.call(h.token(agent), params=tool("list_invoices", contact=EMAIL))
    (item,) = await _flushed(h)
    assert item["arguments_redacted"] is None and item["result_excerpt"] is None
    assert EMAIL not in str(item)


@pytest.mark.asyncio
async def test_an_allowed_call_carries_redacted_argument_and_result_excerpts_when_capture_is_on() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, payload_capture=True)
    await h.call(h.token(agent), params=tool("list_invoices", contact=EMAIL, invoice_id="INV-1"))
    (item,) = await _flushed(h)
    args = item["arguments_redacted"]
    assert isinstance(args, dict) and set(args) == {"text", "truncated", "original_bytes"}
    assert "INV-1" in args["text"]  # ordinary values are kept
    assert EMAIL not in str(item) and "[REDACTED:EMAIL]" in args["text"]  # PII is not
    result = item["result_excerpt"]
    assert isinstance(result, dict) and set(result) == {"text", "truncated", "original_bytes"} and result["text"]


@pytest.mark.asyncio
async def test_a_refused_call_keeps_a_redacted_argument_excerpt_and_no_result() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, payload_capture=True)
    await h.call(h.token(agent), params=tool("delete_invoice", invoice_id="INV-9", contact=EMAIL))
    (item,) = await _flushed(h)
    assert item["decision"] == "BLOCK"
    assert isinstance(item["arguments_redacted"], dict) and "INV-9" in item["arguments_redacted"]["text"]  # type: ignore[index]
    assert EMAIL not in str(item)
    assert item["result_excerpt"] is None


@pytest.mark.asyncio
async def test_secrets_in_a_result_never_reach_the_stored_excerpt() -> None:
    h = Harness()
    agent = h.add_agent(LEAKY, payload_capture=True)
    await h.call(h.token(agent), params=tool("leaky"))
    (item,) = await _flushed(h)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(item)
    assert item["result_excerpt"] is not None


@pytest.mark.asyncio
async def test_a_call_without_arguments_has_no_argument_excerpt() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, payload_capture=True)
    await h.call(h.token(agent), params=tool("list_invoices"))
    (item,) = await _flushed(h)
    assert item["arguments_redacted"] is None and item["result_excerpt"] is not None


@pytest.mark.asyncio
async def test_non_tool_calls_never_carry_payloads() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, payload_capture=True)
    await h.call(h.token(agent), method="tools/list", params={})
    assert await _flushed(h) == []  # only tools/call is recorded at all


@pytest.mark.asyncio
async def test_a_capture_failure_never_changes_the_decision_and_is_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentwall.src.gateway import service

    def boom(_value: object) -> object:
        raise RuntimeError(f"boom with {EMAIL}")

    monkeypatch.setattr(service, "build_excerpt", boom)
    h = Harness()
    agent = h.add_agent(INVOICES_READ, payload_capture=True)
    resp = await h.call(h.token(agent), params=tool("list_invoices", contact=EMAIL))
    assert resp.status_code == 200 and h.upstream.received  # still allowed and forwarded
    (item,) = await _flushed(h)
    assert item["decision"] == "ALLOW" and item["arguments_redacted"] is None  # recorded, without a payload
    assert 'redhand_gateway_payload_captures_total{outcome="failed"} 1' in h.gateway.metrics.render()


@pytest.mark.asyncio
async def test_successful_captures_are_counted() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, payload_capture=True)
    await h.call(h.token(agent), params=tool("list_invoices", invoice_id="INV-1"))
    assert 'redhand_gateway_payload_captures_total{outcome="ok"} 1' in h.gateway.metrics.render()


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["missing", "true", 1, None, "yes"])
async def test_a_missing_or_malformed_capture_flag_denies_the_call(bad: object) -> None:
    """Same rule as safe_mode and budget: a context core did not fully state is not trusted, so an older core
    that sends no flag makes the gateway deny rather than guess whether capture is on."""
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    if bad == "missing":
        del h.core.agents[str(agent)]["payload_capture"]
    else:
        h.core.agents[str(agent)]["payload_capture"] = bad
    resp = await h.call(h.token(agent), params=tool("list_invoices", contact=EMAIL))
    assert resp.status_code == 503 and h.upstream.received == []


@pytest.mark.asyncio
async def test_payload_values_never_appear_in_gateway_logs() -> None:
    from structlog.testing import capture_logs

    h = Harness()
    agent = h.add_agent(LEAKY, payload_capture=True)
    with capture_logs() as logs:
        await h.call(h.token(agent), params=tool("leaky", contact=EMAIL))
        await h.call(h.token(agent), params=tool("not_in_scope", contact=EMAIL))
    assert EMAIL not in str(logs) and "AKIAIOSFODNN7EXAMPLE" not in str(logs)


@pytest.mark.asyncio
async def test_captured_payloads_stay_within_core_limits() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, payload_capture=True)
    # Many moderate fields (a single string over the 16 KB scan budget becomes a marker instead, see test_capture).
    fields = {f"field_{i}": "y" * 400 for i in range(20)}
    await h.call(h.token(agent), params=tool("list_invoices", contact=EMAIL, **fields))
    (item,) = await _flushed(h)
    for key in ("arguments_redacted", "result_excerpt"):
        payload = item[key]
        assert isinstance(payload, dict)
        assert len(payload["text"]) <= 2048 and isinstance(payload["truncated"], bool)  # type: ignore[index]
    assert item["arguments_redacted"]["truncated"] is True  # type: ignore[index]


# ---------------------------------------------------------------------------
# Exactly-once delivery: a retry or a second flush must never store an event twice
# ---------------------------------------------------------------------------


def test_a_retry_resends_the_same_batch_id_and_the_same_events() -> None:
    """Core ignores a batch id it has stored. If the reply to a stored batch is lost, the retry must carry the
    SAME id and items, or core stores the events a second time under a new id."""
    reporter = FakeReporter()
    rec = EventRecorder(instance_id="gw-1", reporter=reporter)
    rec.record(event(tool_name="first"))
    rec.record(event(tool_name="second"))

    reporter.accept = False  # the reply was lost: the gateway cannot tell the batch was stored
    assert asyncio.run(rec.flush()) is False
    rec.record(event(tool_name="arrived-between-attempts"))
    reporter.accept = True
    assert asyncio.run(rec.flush()) is True

    (_, first_id, _, first_items), (_, retry_id, _, retry_items) = reporter.calls[:2]
    assert retry_id == first_id and retry_items == first_items  # not even the late event joins the retry
    assert asyncio.run(rec.flush()) is True
    assert [i["tool_name"] for i in reporter.calls[2][3]] == ["arrived-between-attempts"]
    assert reporter.calls[2][1] != first_id  # the next batch is new
    assert rec.buffered_count == 0


def test_a_new_batch_gets_a_new_id_after_the_old_one_is_accepted() -> None:
    reporter = FakeReporter()
    rec = EventRecorder(instance_id="gw-1", reporter=reporter)
    rec.record(event())
    asyncio.run(rec.flush())
    rec.record(event())
    asyncio.run(rec.flush())
    assert reporter.calls[0][1] != reporter.calls[1][1]


def test_a_drop_during_a_failed_attempt_is_reported_once_and_not_lost() -> None:
    reporter = FakeReporter()
    rec = EventRecorder(instance_id="gw-1", reporter=reporter, max_buffered=2)
    agent = uuid4()
    for _ in range(3):  # two buffered, one dropped
        rec.record(event(agent_id=agent))
    reporter.accept = False
    asyncio.run(rec.flush())
    rec.record(event(agent_id=agent))  # still full: a second drop while the first batch is waiting
    reporter.accept = True
    asyncio.run(rec.flush())
    asyncio.run(rec.flush())
    gaps = [i["reasons"][0] for call in reporter.calls for i in call[3] if i["method"] == "recorder.gap"]
    assert gaps[0].startswith("1 event(s) dropped") and gaps[-1].startswith("1 event(s) dropped")
    assert len(gaps) == 3 and rec.buffered_count == 0  # the retry repeated the first gap; the second drop got its own


@pytest.mark.asyncio
async def test_a_direct_flush_while_another_is_in_flight_does_not_send_events_twice() -> None:
    """The background loop and the request path can both flush. The second must wait, not re-send the same events."""
    release = asyncio.Event()
    sent: list[tuple[str, list[dict[str, object]]]] = []

    class SlowReporter:
        async def send(self, instance_id: str, batch_id: str, organization_id: UUID, items: list[dict[str, object]]) -> bool:
            sent.append((batch_id, items))
            await release.wait()
            return True

    rec = EventRecorder(instance_id="gw-1", reporter=SlowReporter())
    for name in ("a", "b", "c"):
        rec.record(event(tool_name=name))

    in_flight = asyncio.create_task(rec.flush())
    await asyncio.sleep(0)  # the first flush is now inside send()
    second = asyncio.create_task(rec.flush())  # what the background loop does: a direct call
    await asyncio.sleep(0)
    release.set()
    await asyncio.gather(in_flight, second)

    names = [i["tool_name"] for _, items in sent for i in items]
    assert sorted(names) == ["a", "b", "c"]  # each event exactly once
    assert rec.buffered_count == 0
