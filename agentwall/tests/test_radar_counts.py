"""
Radar evidence from real traffic, gateway side (Phase 4 M4.6b): per organization and check the gateway counts what it scanned, lost and
flagged (before its repeat limit), and sends the totals to core with a report id. Counting is evidence, never enforcement: nothing here may
change a call, lose a finding or carry any text.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from agentwall.src.firewall import radar
from agentwall.src.firewall.radar_fingerprint import rules_fingerprint
from agentwall.src.gateway import radar_scan
from agentwall.src.gateway.metrics import GatewayMetrics
from agentwall.src.gateway.radar_scan import (
    COUNTS_ITEMS_PER_REPORT, MAX_COUNT_PER_REPORT, HttpScanCountsReporter, RadarScanner, ScanCounters, ScanCountsReport,
)

from test_gateway import INVOICES_READ, ORG, FakeFindingsReporter, FakeScanCountsReporter, Harness, tool
from test_gateway_radar import INJECTION, SECRET_MARKER, XSS, call, wired

OBSERVE = frozenset({"injection", "output"})
FP = "0123456789abcdef"


def sent_items(h: Harness) -> list[dict[str, Any]]:
    return [item for report in h.counts_reporter.reports for item in report.items]


async def flushed(h: Harness) -> list[dict[str, Any]]:
    h.radar.flush_counts()
    await h.radar.wait_idle()
    return sent_items(h)


def item_for(items: list[dict[str, Any]], kind: str, org: UUID | None = None) -> dict[str, Any]:
    """The totals for one check (and organization) across every report sent so far: counts also go out when a finding is reported, so there may be several."""
    mine = [i for i in items if i["kind"] == kind and (org is None or i["organization_id"] == str(org))]
    assert mine, f"nothing was reported for {kind}"
    rules: dict[str, list[int]] = {}
    for i in mine:
        for r in i["rules"]:
            slot = rules.setdefault(r["rule_id"], [0, 0])
            slot[0] += r["flagged"]
            slot[1] += r["strong"]
    return {
        "organization_id": mine[0]["organization_id"], "kind": kind,
        **{f: sum(i[f] for i in mine) for f in ("scanned", "dropped", "errors", "flagged", "strong")},
        "rules": [{"rule_id": k, "flagged": v[0], "strong": v[1]} for k, v in sorted(rules.items())],
    }


def stand_alone(**kwargs: Any) -> tuple[RadarScanner, FakeFindingsReporter, FakeScanCountsReporter]:
    findings, counts = FakeFindingsReporter(), FakeScanCountsReporter()
    scanner = RadarScanner(reporter=findings, retry_delays=(), counts_reporter=counts, fingerprint=FP, **kwargs)
    return scanner, findings, counts


def submit(scanner: RadarScanner, org: UUID, text: str = "Invoice 1001 paid", kinds: frozenset[str] = OBSERVE, agent: UUID | None = None) -> bool:
    return scanner.submit(organization_id=org, agent_id=agent or uuid4(), server="xero", tool="t", tool_names=frozenset(), kinds=kinds, result=text)  # type: ignore[arg-type]  # a frozenset of the two literals


# --- what is counted, through the real gateway ------------------------------------------------------------------------

async def test_an_attack_is_counted_as_scanned_flagged_and_strong_with_the_rules_that_fired() -> None:
    h, token = wired(text=INJECTION)
    await call(h, token)
    items = await flushed(h)
    injection, output = item_for(items, "injection"), item_for(items, "output")
    assert (injection["scanned"], injection["flagged"], injection["dropped"], injection["errors"]) == (1, 1, 0, 0) and injection["strong"] == 1
    assert injection["rules"] and all(r["rule_id"].startswith("RAD-INJ-") and r["flagged"] == 1 for r in injection["rules"])
    assert (output["scanned"], output["flagged"], output["strong"], output["rules"]) == (1, 0, 0, [])  # the output check scanned it too and found nothing


async def test_a_harmless_result_is_counted_as_scanned_and_nothing_else() -> None:
    h, token = wired(text="Invoice 1001 paid on 3 March, total 120.00")
    await call(h, token)
    for item in await flushed(h):
        assert (item["scanned"], item["flagged"], item["strong"], item["rules"]) == (1, 0, 0, [])


async def test_counts_add_up_across_calls_and_every_flagged_result_is_counted_even_when_reports_are_throttled() -> None:
    h, token = wired(text=INJECTION)
    for _ in range(3):
        await call(h, token)
    assert len(h.findings_reporter.reports) == 1  # the repeat limit: the same finding is reported once in 30 seconds...
    injection = item_for(await flushed(h), "injection")
    assert (injection["scanned"], injection["flagged"]) == (3, 3)  # ...but every one of the three results is counted
    assert all(r["flagged"] == 3 for r in injection["rules"])


async def test_each_organization_is_counted_on_its_own() -> None:
    h = Harness()
    other = UUID("00000000-0000-0000-0000-0000000000f0")
    a = h.add_agent(INVOICES_READ, radar_mode="observe", output_check_mode="observe")
    b = h.add_agent(INVOICES_READ, org=other, radar_mode="observe", output_check_mode="observe")
    h.upstream.reply_text = INJECTION
    await h.call(h.token(a), params=tool("list_invoices"))
    await h.call(h.token(a), params=tool("list_invoices"))
    h.upstream.reply_text = "Invoice paid"
    await h.call(h.token(b, org=other), params=tool("list_invoices"))
    await h.radar.wait_idle()
    items = await flushed(h)
    mine, theirs = item_for(items, "injection", ORG), item_for(items, "injection", other)
    assert (mine["scanned"], mine["flagged"]) == (2, 2) and (theirs["scanned"], theirs["flagged"]) == (1, 0)
    assert len({(i["organization_id"], i["kind"]) for i in items}) == 4  # two organizations, two checks each


async def test_a_check_that_is_off_is_not_counted_and_both_off_counts_nothing() -> None:
    h, token = wired("off", "observe", INJECTION + XSS)
    await call(h, token)
    items = await flushed(h)
    assert {i["kind"] for i in items} == {"output"}
    h, token = wired("off", "off", INJECTION)
    await call(h, token)
    assert await flushed(h) == [] and h.counts_reporter.reports == []


async def test_what_is_sent_is_numbers_and_rule_ids_only_never_any_text_tool_or_agent() -> None:
    h, token = wired(text=INJECTION + XSS + SECRET_MARKER)
    await call(h, token)
    await flushed(h)
    report = h.counts_reporter.reports[0]
    assert set(report.items[0]) == {"organization_id", "kind", "scanned", "dropped", "errors", "flagged", "strong", "rules"}
    assert all(set(r) == {"rule_id", "flagged", "strong"} for i in report.items for r in i["rules"])
    dumped = json.dumps([[dict(i) for i in r.items] for r in h.counts_reporter.reports])
    for fragment in ("attacker@evil", "customer list", "onerror", "document.cookie", SECRET_MARKER, "list_invoices", "xero"):
        assert fragment not in dumped
    assert report.rules_fingerprint == FP and isinstance(report.report_id, UUID)


async def test_counts_go_out_with_a_finding_so_a_stored_finding_is_never_far_ahead_of_its_count() -> None:
    h, token = wired(text=INJECTION)
    await call(h, token)  # no flush_counts() here: the finding report itself triggers the counts report
    assert h.findings_reporter.reports and h.counts_reporter.reports
    injection = item_for(sent_items(h), "injection")
    assert (injection["scanned"], injection["flagged"]) == (1, 1)


async def test_a_busy_gateway_flushes_on_activity_because_cloud_run_pauses_timers_between_requests() -> None:
    now = [1000.0]
    scanner, _, counts = stand_alone(clock=lambda: now[0], counts_flush_seconds=60.0)
    org = uuid4()
    assert submit(scanner, org)  # harmless: no finding, so nothing triggers a flush
    await scanner.wait_idle()
    assert counts.reports == []  # a minute has not passed
    now[0] += 61.0
    assert submit(scanner, org)  # the next result finds the flush overdue and sends everything counted so far
    await scanner.wait_idle()
    assert sum(i["scanned"] for r in counts.reports for i in r.items if i["kind"] == "injection") == 2
    now[0] += 5.0
    assert submit(scanner, org)
    await scanner.wait_idle()
    assert sum(len(r.items) for r in counts.reports) == 2  # only five seconds later: not due again, still held
    await scanner.aclose()


# --- losses are counted ------------------------------------------------------------------------------------------------

async def test_results_dropped_because_the_queue_is_full_are_counted_as_lost() -> None:
    scanner, _, counts = stand_alone()
    org = uuid4()
    accepted = [submit(scanner, org) for _ in range(radar_scan.QUEUE_SIZE + 4)]
    assert accepted.count(False) == 4
    await scanner.wait_idle()
    scanner.flush_counts()
    await scanner.wait_idle()
    items = [i for r in counts.reports for i in r.items]
    assert {i["kind"] for i in items} == {"injection", "output"}  # something WAS reported (a loop over nothing would pass for the wrong reason)
    for item in items:
        assert (item["scanned"], item["dropped"]) == (radar_scan.QUEUE_SIZE, 4)
    await scanner.aclose()


async def test_a_scan_that_fails_is_counted_as_an_error_and_never_as_scanned(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner, findings, counts = stand_alone()
    monkeypatch.setattr(radar_scan.radar, "scan_result", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    org = uuid4()
    assert submit(scanner, org, INJECTION)
    await scanner.wait_idle()
    scanner.flush_counts()
    await scanner.wait_idle()
    items = [i for r in counts.reports for i in r.items]
    assert {i["kind"] for i in items} == {"injection", "output"}  # the failed scan is reported, as a loss
    for item in items:
        assert (item["scanned"], item["errors"], item["flagged"]) == (0, 1, 0)
    assert findings.reports == []
    await scanner.aclose()


async def test_a_counting_bug_changes_no_call_and_loses_no_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    h, token = wired(text=INJECTION)

    def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("counting bug")

    assert h.radar.counters is not None
    monkeypatch.setattr(h.radar.counters, "note_scan", broken)
    monkeypatch.setattr(h.radar.counters, "note_loss", broken)
    response = await call(h, token)
    assert response.status_code == 200 and response.body["result"]["content"][0]["text"] == INJECTION
    assert len(h.findings_reporter.reports) == 1  # the finding still reached core


# --- delivery ----------------------------------------------------------------------------------------------------------

async def test_a_big_flush_is_split_into_reports_core_accepts_each_with_its_own_id() -> None:
    scanner, _, counts = stand_alone()
    orgs = [uuid4() for _ in range(COUNTS_ITEMS_PER_REPORT * 2 + 7)]
    assert scanner.counters is not None
    for org in orgs:
        scanner.counters.note_scan(org, frozenset({"output"}), [])
    scanner.flush_counts()
    await scanner.wait_idle()
    assert [len(r.items) for r in counts.reports] == [50, 50, 7] and len({r.report_id for r in counts.reports}) == 3
    assert {i["organization_id"] for r in counts.reports for i in r.items} == {str(o) for o in orgs}


async def test_an_empty_flush_sends_nothing() -> None:
    scanner, _, counts = stand_alone()
    scanner.flush_counts()
    await scanner.wait_idle()
    assert counts.reports == []


async def test_undeliverable_counts_are_kept_and_sent_again_but_a_refusal_is_not_retried_forever() -> None:
    scanner, _, counts = stand_alone()
    org = uuid4()
    assert scanner.counters is not None
    scanner.counters.note_scan(org, frozenset({"output"}), [])
    counts.outcomes = ["retry"]  # core unreachable: the report fails after its retries
    scanner.flush_counts()
    await scanner.wait_idle()
    scanner.flush_counts()  # the next minute: the same totals go out again
    await scanner.wait_idle()
    assert [i["scanned"] for r in counts.reports for i in r.items] == [1, 1] and len({r.report_id for r in counts.reports}) == 2
    counts.reports.clear()
    scanner.counters.note_scan(org, frozenset({"output"}), [])
    counts.outcomes = ["drop"]  # core refused it (a 4xx): sending it again would be refused again
    scanner.flush_counts()
    await scanner.wait_idle()
    scanner.flush_counts()
    await scanner.wait_idle()
    assert len(counts.reports) == 1


async def test_counts_that_could_not_even_be_started_are_kept_for_the_next_report() -> None:
    gate = asyncio.Event()

    class Stuck:
        def __init__(self) -> None:
            self.started = 0

        async def send(self, report: ScanCountsReport) -> Any:
            self.started += 1
            await gate.wait()  # core is hanging: nothing completes
            return "ok"

    stuck = Stuck()
    scanner = RadarScanner(reporter=FakeFindingsReporter(), retry_delays=(), counts_reporter=stuck, fingerprint=FP)  # type: ignore[arg-type]  # a duck-typed reporter
    assert scanner.counters is not None
    for _ in range(radar_scan.MAX_IN_FLIGHT):
        scanner.counters.note_scan(uuid4(), frozenset({"output"}), [])
        scanner.flush_counts()
    await asyncio.sleep(0)
    late = uuid4()
    scanner.counters.note_scan(late, frozenset({"output"}), [])
    scanner.flush_counts()  # the 21st report cannot start: too many are in flight
    kept = scanner.counters.drain()
    assert [i["organization_id"] for i in kept] == [str(late)] and kept[0]["scanned"] == 1  # its counts were put back, not thrown away
    gate.set()
    await scanner.wait_idle()
    await scanner.aclose()


async def test_the_flush_runs_on_a_timer_and_shutdown_sends_the_last_counts() -> None:
    scanner, _, counts = stand_alone(counts_flush_seconds=0.02)
    assert submit(scanner, uuid4())
    await scanner.wait_idle()
    for _ in range(100):
        if counts.reports:
            break
        await asyncio.sleep(0.01)
    assert counts.reports, "no report arrived on the timer"
    counts.reports.clear()
    assert scanner.counters is not None
    scanner.counters.note_scan(uuid4(), frozenset({"output"}), [])
    await scanner.aclose()
    assert sum(len(r.items) for r in counts.reports) == 1  # the final minute is not lost on a restart


async def test_without_a_counts_reporter_nothing_is_counted_and_no_timer_runs() -> None:
    scanner = RadarScanner(reporter=FakeFindingsReporter(), retry_delays=())
    assert submit(scanner, uuid4(), INJECTION)
    await scanner.wait_idle()
    assert scanner.counters is None and scanner._flusher is None
    scanner.flush_counts()  # a no-op, not an error
    await scanner.aclose()


def test_the_fingerprint_sent_is_the_rules_this_process_runs_and_marks_the_helper_model() -> None:
    plain = RadarScanner(reporter=FakeFindingsReporter(), counts_reporter=FakeScanCountsReporter())
    assert plain._fingerprint == rules_fingerprint() and not plain._fingerprint.endswith("+model")
    with_model = RadarScanner(reporter=FakeFindingsReporter(), counts_reporter=FakeScanCountsReporter(), use_model=True)
    assert with_model._fingerprint == rules_fingerprint() + "+model"


async def test_report_outcomes_are_counted_in_the_metrics() -> None:
    metrics = GatewayMetrics()
    scanner, _, counts = stand_alone(metrics=metrics)
    assert scanner.counters is not None
    scanner.counters.note_scan(uuid4(), frozenset({"output"}), [])
    scanner.flush_counts()
    await scanner.wait_idle()
    counts.outcomes = ["drop"]
    scanner.counters.note_scan(uuid4(), frozenset({"output"}), [])
    scanner.flush_counts()
    await scanner.wait_idle()
    text = metrics.render()
    assert 'redhand_gateway_radar_count_reports_total{outcome="ok"} 1' in text and 'redhand_gateway_radar_count_reports_total{outcome="refused"} 1' in text


# --- the counters themselves --------------------------------------------------------------------------------------------

def finding(rule: str, confidence: str = "high", kind: str = "injection") -> radar.Finding:
    return radar.Finding(rule, "override", kind, "high", confidence, "text", (), "fixed")  # type: ignore[arg-type]  # literal-typed fields


def test_one_result_flagged_by_two_rules_counts_once_for_the_check_and_once_per_rule() -> None:
    counters, org = ScanCounters(), uuid4()
    counters.note_scan(org, OBSERVE, [finding("RAD-INJ-001"), finding("RAD-INJ-008", "low"), finding("RAD-OUT-001", kind="output")])
    items = {i["kind"]: i for i in counters.drain()}
    inj = items["injection"]
    assert (inj["scanned"], inj["flagged"], inj["strong"]) == (1, 1, 1)
    assert {r["rule_id"]: (r["flagged"], r["strong"]) for r in inj["rules"]} == {"RAD-INJ-001": (1, 1), "RAD-INJ-008": (1, 0)}
    assert (items["output"]["flagged"], items["output"]["strong"]) == (1, 1)


def test_a_low_confidence_finding_is_flagged_but_not_strong() -> None:
    counters = ScanCounters()
    counters.note_scan(uuid4(), frozenset({"injection"}), [finding("RAD-INJ-001", "low")])
    (item,) = counters.drain()
    assert (item["flagged"], item["strong"]) == (1, 0) and item["rules"] == [{"rule_id": "RAD-INJ-001", "flagged": 1, "strong": 0}]


def test_a_finding_of_a_check_that_was_not_asked_for_is_ignored() -> None:
    counters = ScanCounters()
    counters.note_scan(uuid4(), frozenset({"injection"}), [finding("RAD-OUT-001", kind="output")])
    (item,) = counters.drain()
    assert item["kind"] == "injection" and item["flagged"] == 0 and item["rules"] == []


def test_drain_empties_the_counters_and_restore_puts_them_back_exactly() -> None:
    counters, org = ScanCounters(), uuid4()
    counters.note_scan(org, OBSERVE, [finding("RAD-INJ-001")])
    counters.note_loss(org, OBSERVE, "dropped")
    first = counters.drain()
    assert counters.drain() == []
    counters.restore(first)
    assert counters.drain() == first


def test_a_count_above_what_core_accepts_is_sent_in_pieces_that_add_up_and_stay_consistent() -> None:
    counters, org = ScanCounters(), uuid4()
    counters.note_scan(org, frozenset({"injection"}), [finding("RAD-INJ-001")])
    slot = counters._slot(org, "injection")
    assert slot is not None
    slot.scanned, slot.flagged, slot.strong, slot.rules = 2_500_000, 2_300_000, 100, {"RAD-INJ-001": [2_300_000, 100]}
    pieces = counters.drain()
    assert len(pieces) == 3 and all(p["scanned"] <= MAX_COUNT_PER_REPORT for p in pieces)
    assert sum(p["scanned"] for p in pieces) == 2_500_000 and sum(p["flagged"] for p in pieces) == 2_300_000 and sum(p["strong"] for p in pieces) == 100
    for p in pieces:
        assert p["flagged"] <= p["scanned"] and p["strong"] <= p["flagged"]
        for r in p["rules"]:
            assert r["flagged"] <= p["scanned"] and r["strong"] <= r["flagged"] <= MAX_COUNT_PER_REPORT


def test_inconsistent_leftovers_are_dropped_and_never_loop() -> None:
    counters, org = ScanCounters(), uuid4()
    slot = counters._slot(org, "output")
    assert slot is not None
    slot.rules = {"RAD-OUT-001": [5, 5]}  # rule counts with nothing scanned could never be accepted
    assert counters.drain() == [] and counters.drain() == []


def test_at_most_the_configured_number_of_organizations_are_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(radar_scan, "MAX_COUNTED_ORGANIZATIONS", 3)
    counters = ScanCounters()
    orgs = [uuid4() for _ in range(5)]
    for org in orgs:
        counters.note_scan(org, frozenset({"output"}), [])
    assert {i["organization_id"] for i in counters.drain()} == {str(o) for o in orgs[:3]}  # a new organization is never counted, so it can never look ready


# --- the HTTP reporter -------------------------------------------------------------------------------------------------

def make_report() -> ScanCountsReport:
    return ScanCountsReport(uuid4(), FP, ({"organization_id": str(uuid4()), "kind": "output", "scanned": 3, "dropped": 0, "errors": 0, "flagged": 0, "strong": 0, "rules": []},))


@pytest.mark.parametrize(("status", "outcome"), [(200, "ok"), (422, "drop"), (401, "drop"), (404, "drop"), (429, "retry"), (500, "retry"), (503, "retry")])
async def test_the_http_reporter_maps_core_answers_to_outcomes(status: int, outcome: str) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json={})

    reporter = HttpScanCountsReporter(core_url="http://core/", service_token="s3cret-token", http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    report = make_report()
    assert await reporter.send(report) == outcome
    (request,) = seen
    assert str(request.url) == "http://core/internal/v1/radar/scan-counts" and request.headers["authorization"] == "Bearer s3cret-token"
    body = json.loads(request.content)
    assert body["report_id"] == str(report.report_id) and body["rules_fingerprint"] == FP and body["items"] == list(report.items)


async def test_the_http_reporter_retries_a_network_error_and_drops_when_it_has_no_token() -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    down = HttpScanCountsReporter(core_url="http://core", service_token="t", http_client=httpx.AsyncClient(transport=httpx.MockTransport(broken)))
    assert await down.send(make_report()) == "retry"
    assert await HttpScanCountsReporter(core_url="http://core", service_token=None).send(make_report()) == "drop"
