"""
Prompt Injection Radar and output checks in the gateway (Phase 4 M4.3, docs/adr/0015-radar-in-the-gateway.md).

OBSERVE ONLY. A tool result is handed to a bounded background queue after the gateway has already decided what to return;
a worker scans it and reports findings to core. The scan can never change, delay or block a call: `submit()` is synchronous and
does no I/O, a full queue drops the work (counted), and any scanner or network error is counted and swallowed. Block mode does
not exist. A finding never carries the scanned text, only a fixed rule id, family, severity, confidence, place and evasion tags.

Evidence from real traffic (M4.6b): the scanner also counts, per organization and check, how many results it scanned, lost (queue full, scan
error) and flagged, and how many a rule flagged, BEFORE the repeat limit and before core applies suppressions. Totals go to core about once a
minute with a report id (a retried report is counted once). Numbers only, no text. This is evidence, not enforcement: a counting or reporting
failure changes no call and no finding.

Cost: the rules read at most 16 KiB from each end of a result (about 1 ms per KiB); the optional second-stage model adds about
8 ms at most. That work runs on a worker thread, never inline, but it still competes for the same CPU, so it is measured
(scripts/latency_baseline.py) and the model is off unless AGENTWALL_RADAR_MODEL_ENABLED is set.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
import time
from typing import Any, Protocol
from uuid import UUID, uuid4

import httpx
import structlog

from ..firewall import radar
from ..firewall.injection_model import RULES_AND_MODEL
from ..firewall.radar_fingerprint import rules_fingerprint
from .dispatch import SHUTDOWN_WAIT_SECONDS, Outcome, ReportDispatcher, outcome_for_status
from .metrics import GatewayMetrics

logger = structlog.get_logger(__name__)

QUEUE_SIZE = 16  # results waiting for a scan; each is already in memory for its own request, so this bounds the extra hold
MAX_IN_FLIGHT = 20
RETRY_DELAYS = (0.5, 1.0, 2.0, 4.0)
THROTTLE_SECONDS = 30.0  # the same (agent, rule, tool, place) is reported at most this often; core also coalesces
MAX_THROTTLE_KEYS = 20_000
MAX_ITEMS = 20
COUNTS_FLUSH_SECONDS = 60.0
COUNTS_ITEMS_PER_REPORT = 50  # core accepts at most 50 items per report
MAX_COUNT_PER_REPORT = 1_000_000  # core refuses a whole report with a larger number, so a larger count is sent in pieces
LOOP_RULE_ID = "RAD-LOOP-001"
MAX_COUNTED_ORGANIZATIONS = 5_000  # beyond this, a new organization is not counted (and so can never look ready); counted in metrics

__all__ = [
    "FindingsReport", "FindingsReporter", "HttpFindingsReporter", "HttpScanCountsReporter", "RadarScanner", "ScanCounters",
    "ScanCountsReport", "ScanCountsReporter", "kinds_for",
]


def kinds_for(radar_mode: str, output_check_mode: str) -> frozenset[radar.Kind]:
    """Which kinds of check are on. Only an explicit "observe" turns one on; anything else is off."""
    kinds: set[radar.Kind] = set()
    if radar_mode == "observe":
        kinds.add("injection")
    if output_check_mode == "observe":
        kinds.add("output")
    return frozenset(kinds)


@dataclass(frozen=True, slots=True)
class FindingsReport:
    organization_id: UUID
    agent_id: UUID
    items: tuple[dict[str, Any], ...]


class FindingsReporter(Protocol):
    async def send(self, report: FindingsReport) -> Outcome: ...


class HttpFindingsReporter:
    def __init__(self, *, core_url: str, service_token: str | None, http_client: httpx.AsyncClient | None = None) -> None:
        self._url = core_url.rstrip("/") + "/internal/v1/findings"
        self._token = service_token
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0))

    async def send(self, report: FindingsReport) -> Outcome:
        if not self._token:
            return "drop"
        try:
            response = await self._http.post(
                self._url, headers={"Authorization": f"Bearer {self._token}"},
                json={"organization_id": str(report.organization_id), "agent_id": str(report.agent_id), "items": list(report.items)},
            )
        except httpx.HTTPError as exc:
            logger.warning("Findings report failed: core unreachable", error_type=type(exc).__name__)
            return "retry"
        if response.status_code != 200:
            logger.warning("Findings report refused", status=response.status_code)
        return outcome_for_status(response.status_code)


@dataclass(frozen=True, slots=True)
class ScanCountsReport:
    report_id: UUID
    rules_fingerprint: str
    items: tuple[dict[str, Any], ...]


class ScanCountsReporter(Protocol):
    async def send(self, report: ScanCountsReport) -> Outcome: ...


class HttpScanCountsReporter:
    def __init__(self, *, core_url: str, service_token: str | None, http_client: httpx.AsyncClient | None = None) -> None:
        self._url = core_url.rstrip("/") + "/internal/v1/radar/scan-counts"
        self._token = service_token
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0))

    async def send(self, report: ScanCountsReport) -> Outcome:
        if not self._token:
            return "drop"
        try:
            response = await self._http.post(
                self._url, headers={"Authorization": f"Bearer {self._token}"},
                json={"report_id": str(report.report_id), "rules_fingerprint": report.rules_fingerprint, "items": list(report.items)},
            )
        except httpx.HTTPError as exc:
            logger.warning("Scan counts report failed: core unreachable", error_type=type(exc).__name__)
            return "retry"
        if response.status_code != 200:
            logger.warning("Scan counts report refused", status=response.status_code)
        return outcome_for_status(response.status_code)


_FIELDS = ("scanned", "dropped", "errors", "flagged", "strong")


class _KindCounts:
    __slots__ = ("scanned", "dropped", "errors", "flagged", "strong", "rules")

    def __init__(self) -> None:
        self.scanned = self.dropped = self.errors = self.flagged = self.strong = 0
        self.rules: dict[str, list[int]] = {}  # rule id -> [results it flagged, results it flagged strongly]

    def empty(self) -> bool:
        return not any(getattr(self, f) for f in _FIELDS) and not self.rules


class ScanCounters:
    """
    Totals per organization and check since the last report. Single-threaded by design (the event loop owns it). Counts are taken before the
    gateway's repeat limit and before core's suppressions, so neither can hide a result from the evidence. `drain()` hands over what has
    accumulated (in pieces core will accept) and `restore()` puts back what could not be delivered.
    """

    def __init__(self) -> None:
        self._orgs: dict[UUID, dict[radar.Kind, _KindCounts]] = {}

    def _slot(self, org: UUID, kind: radar.Kind) -> _KindCounts | None:
        by_kind = self._orgs.get(org)
        if by_kind is None:
            if len(self._orgs) >= MAX_COUNTED_ORGANIZATIONS:
                return None
            by_kind = self._orgs[org] = {}
        return by_kind.setdefault(kind, _KindCounts())

    def note_loss(self, org: UUID, kinds: frozenset[radar.Kind], field: str) -> None:
        """A result that was not scanned: "dropped" (queue full) or "errors" (the scan failed)."""
        for kind in kinds:
            slot = self._slot(org, kind)
            if slot is not None:
                setattr(slot, field, getattr(slot, field) + 1)

    def note_scan(self, org: UUID, kinds: frozenset[radar.Kind], findings: Any) -> None:
        for kind in kinds:
            slot = self._slot(org, kind)
            if slot is None:
                continue
            mine = [f for f in findings if f.kind == kind]
            slot.scanned += 1
            slot.flagged += 1 if mine else 0
            slot.strong += 1 if any(f.actionable for f in mine) else 0
            for rule_id in {f.rule_id for f in mine}:
                counts = slot.rules.setdefault(rule_id, [0, 0])
                counts[0] += 1
                counts[1] += 1 if any(f.rule_id == rule_id and f.actionable for f in mine) else 0

    def drain(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for org, by_kind in list(self._orgs.items()):
            for kind, counts in list(by_kind.items()):
                while not counts.empty():
                    take = {f: min(getattr(counts, f), MAX_COUNT_PER_REPORT) for f in _FIELDS}
                    if not any(take.values()):
                        counts.rules.clear()  # per-rule leftovers with nothing scanned cannot be sent (they would be refused): drop them, never loop
                        break
                    rules = []
                    for rule_id, pair in sorted(counts.rules.items()):
                        flagged, strong = min(pair[0], take["scanned"]), min(pair[1], take["scanned"])
                        rules.append({"rule_id": rule_id, "flagged": flagged, "strong": min(strong, flagged)})
                        pair[0] -= flagged
                        pair[1] -= min(strong, flagged)
                    for f in _FIELDS:
                        setattr(counts, f, getattr(counts, f) - take[f])
                    counts.rules = {r: p for r, p in counts.rules.items() if p[0] or p[1]}
                    out.append({"organization_id": str(org), "kind": kind, **take, "rules": rules})
            del self._orgs[org]
        return out

    def restore(self, items: list[dict[str, Any]]) -> None:
        """Puts undelivered totals back so the next report carries them (a restored item is still consistent: it was valid when drained)."""
        for item in items:
            slot = self._slot(UUID(item["organization_id"]), item["kind"])
            if slot is None:
                continue
            for f in _FIELDS:
                setattr(slot, f, getattr(slot, f) + item[f])
            for rule in item["rules"]:
                counts = slot.rules.setdefault(rule["rule_id"], [0, 0])
                counts[0] += rule["flagged"]
                counts[1] += rule["strong"]


@dataclass(frozen=True, slots=True)
class _Job:
    organization_id: UUID
    agent_id: UUID
    server: str
    tool: str
    tool_names: frozenset[str]
    kinds: frozenset[radar.Kind]
    result: Any


def finding_item(finding: radar.Finding, tool: str, server: str) -> dict[str, Any]:
    """The fields core accepts for one finding. `would_block` means "this would have been alerted on" (not low confidence)."""
    return {
        "rule_id": finding.rule_id, "kind": finding.kind, "family": finding.family, "severity": finding.severity,
        "confidence": finding.confidence, "place": finding.where, "evasion": list(finding.evasion),
        "tool_name": tool[:128], "server": server[:63], "would_block": finding.actionable, "occurrences": 1,
    }


class RadarScanner:
    def __init__(
        self, *, reporter: FindingsReporter, metrics: GatewayMetrics | None = None, use_model: bool = False,
        retry_delays: tuple[float, ...] = RETRY_DELAYS, clock: Any = time.monotonic,
        counts_reporter: ScanCountsReporter | None = None, counts_flush_seconds: float = COUNTS_FLUSH_SECONDS,
        fingerprint: str | None = None,
    ) -> None:
        self._metrics = metrics
        self._detectors = RULES_AND_MODEL if use_model else radar.DEFAULT_DETECTORS
        self._clock = clock
        self._queue: asyncio.Queue[_Job] | None = None
        self._worker: asyncio.Task[None] | None = None
        self._flusher: asyncio.Task[None] | None = None
        self._counts_flush_seconds = counts_flush_seconds
        self._last_flush = clock()
        self._fingerprint = fingerprint if fingerprint is not None else rules_fingerprint(model_enabled=use_model)
        self._counters: ScanCounters | None = ScanCounters() if counts_reporter is not None else None
        self._counts_reporter = counts_reporter
        self._counts_dispatcher: ReportDispatcher[ScanCountsReport] | None = None
        if counts_reporter is not None:
            self._counts_dispatcher = ReportDispatcher(
                name="scan-counts", send=lambda report: counts_reporter.send(report), count=self._count_counts_report,
                retry_delays=retry_delays, max_in_flight=lambda: MAX_IN_FLIGHT, on_failed=self._restore_counts,
            )
        self._throttle: OrderedDict[tuple[UUID, str, str, str, str], float] = OrderedDict()
        self._reporter = reporter
        self._dispatcher: ReportDispatcher[FindingsReport] = ReportDispatcher(
            name="findings", send=lambda report: self._reporter.send(report), count=self._count_report,
            retry_delays=retry_delays, max_in_flight=lambda: MAX_IN_FLIGHT,
        )

    # -- the gateway's side: synchronous, no I/O ------------------------------------------------------------
    def submit(
        self, *, organization_id: UUID, agent_id: UUID, server: str, tool: str, tool_names: frozenset[str],
        kinds: frozenset[radar.Kind], result: Any,
    ) -> bool:
        """Queues a result for scanning. Never raises or blocks. Returns False when nothing was queued."""
        if not kinds:
            return False
        try:
            queue = self._ensure_worker()
            queue.put_nowait(_Job(organization_id, agent_id, server, tool, tool_names, kinds, result))
        except (asyncio.QueueFull, RuntimeError):  # full, or no running loop: only possible outside a request
            self._count_scan("dropped")
            self._note_loss(organization_id, kinds, "dropped")
            return False
        return True

    def _ensure_worker(self) -> asyncio.Queue[_Job]:
        if self._queue is None:
            self._queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        loop = asyncio.get_running_loop()
        if self._worker is None or self._worker.done():
            self._worker = loop.create_task(self._run(self._queue))
        if self._counters is not None and (self._flusher is None or self._flusher.done()):
            self._flusher = loop.create_task(self._flush_loop())
        return self._queue

    def report_loop(self, *, organization_id: UUID, agent_id: UUID, server: str, tool: str) -> bool:
        """Reports that an agent repeated one call more often than its organization's loop limit (Phase 4 M6). See `report_finding`."""
        metrics = self._metrics

        def throttled() -> None:
            if metrics is not None:
                metrics.record_loop("report_throttled")

        return self.report_finding(
            organization_id=organization_id, agent_id=agent_id, server=server, tool=tool,
            rule_id=LOOP_RULE_ID, kind="loop", family="loop", severity="medium", on_throttled=throttled,
        )

    def report_finding(
        self, *, organization_id: UUID, agent_id: UUID, server: str, tool: str, rule_id: str, kind: str, family: str, severity: str,
        detail: str | None = None, on_throttled: Callable[[], None] | None = None,
    ) -> bool:
        """
        Reports a finding the gateway raised itself, from a call and not from a scanned result (a repeated call, an address outside an agent's
        list). Uses the same reporter, retry and bounded backlog as the Radar's findings, and the same repeat limit: one report per agent, rule,
        tool and server every THROTTLE_SECONDS (core also coalesces), so a count in a finding is "at least". Only counts, names and a coarse
        host go out: never arguments. Synchronous, no I/O, never raises or waits; such a finding changes no decision. False when not queued.
        """
        try:
            now = self._clock()
            key = (agent_id, rule_id, tool, "call", server)
            last = self._throttle.get(key)
            if last is not None and now - last < THROTTLE_SECONDS:
                if on_throttled is not None:
                    on_throttled()
                return False
            self._throttle[key] = now
            self._throttle.move_to_end(key)
            while len(self._throttle) > MAX_THROTTLE_KEYS:
                self._throttle.popitem(last=False)
            item: dict[str, Any] = {
                "rule_id": rule_id, "kind": kind, "family": family, "severity": severity, "confidence": "high", "place": "call",
                "evasion": [], "tool_name": tool[:128], "server": server[:63], "would_block": False, "occurrences": 1,
            }
            if detail is not None:
                item["detail"] = detail
            sent = self._dispatcher.submit(FindingsReport(organization_id, agent_id, (item,)))
            if not sent:
                self._throttle.pop(key, None)  # not queued: the next occurrence is reported
            return sent
        except Exception as exc:  # noqa: BLE001  a finding raised from a call is a side effect and must never affect it
            logger.warning("Finding could not be queued", error_type=type(exc).__name__)
            return False

    # -- the worker -----------------------------------------------------------------------------------------
    async def _run(self, queue: asyncio.Queue[_Job]) -> None:
        while True:
            job = await queue.get()
            try:
                await self._handle(job)
            except Exception as exc:  # noqa: BLE001  one bad result must not stop the scanner; observe mode changes no decision
                logger.warning("Radar worker error", error_type=type(exc).__name__)
                self._count_scan("error")
            finally:
                queue.task_done()
            if self._flush_due():  # Cloud Run pauses timers while no request is running, so a busy gateway also flushes on activity
                self.flush_counts()

    async def _handle(self, job: _Job) -> None:
        started = time.perf_counter()
        try:
            report = await asyncio.to_thread(
                radar.scan_result, job.result, radar.ScanContext(tool_names=job.tool_names), job.kinds, self._detectors,
            )
        except Exception as exc:  # noqa: BLE001  see above
            logger.warning("Radar scan failed", error_type=type(exc).__name__)
            self._count_scan("error")
            self._note_loss(job.organization_id, job.kinds, "errors")
            return
        self._observe_duration((time.perf_counter() - started) * 1000)
        self._count_scan("ok")
        self._note_scan(job, report.findings)  # before the repeat limit below, so that cannot hide a result from the evidence
        if report.truncated:
            self._count_scan("truncated")
        now = self._clock()
        items: list[dict[str, Any]] = []
        for finding in report.findings:
            if self._metrics is not None:
                self._metrics.record_radar_finding(finding.kind)
            key = (job.agent_id, finding.rule_id, job.tool, finding.where, job.server)
            last = self._throttle.get(key)
            if last is not None and now - last < THROTTLE_SECONDS:
                self._count_scan("throttled")
                continue
            self._throttle[key] = now
            self._throttle.move_to_end(key)
            while len(self._throttle) > MAX_THROTTLE_KEYS:
                self._throttle.popitem(last=False)
            if len(items) < MAX_ITEMS:
                items.append(finding_item(finding, job.tool, job.server))
        sent = bool(items) and self._dispatcher.submit(FindingsReport(job.organization_id, job.agent_id, tuple(items)))
        if items and not sent:
            for item in items:  # not sent: forget the throttle so the next occurrence is reported
                self._throttle.pop((job.agent_id, item["rule_id"], job.tool, item["place"], job.server), None)
        if sent:
            self.flush_counts()  # the counts for what was just reported go out with it, so a stored finding is never ahead of its count for long

    # -- lifecycle ------------------------------------------------------------------------------------------
    async def wait_idle(self) -> None:
        """Waits until queued scans and their reports are done (tests and shutdown)."""
        if self._queue is not None:
            await self._queue.join()
        await self._dispatcher.wait_idle()
        if self._counts_dispatcher is not None:
            await self._counts_dispatcher.wait_idle()

    async def aclose(self, timeout: float = SHUTDOWN_WAIT_SECONDS) -> None:
        if self._worker is not None:
            self._worker.cancel()
        if self._flusher is not None:
            self._flusher.cancel()
        self.flush_counts()  # one last report so a restart does not lose the final minute
        await self._dispatcher.aclose(timeout)
        if self._counts_dispatcher is not None:
            await self._counts_dispatcher.aclose(timeout)

    # -- evidence counts ------------------------------------------------------------------------------------
    def _flush_due(self) -> bool:
        return self._counters is not None and self._clock() - self._last_flush >= self._counts_flush_seconds

    def _note_loss(self, org: UUID, kinds: frozenset[radar.Kind], field: str) -> None:
        if self._counters is None:
            return
        try:
            self._counters.note_loss(org, kinds, field)
        except Exception as exc:  # noqa: BLE001  counting is evidence, never enforcement: a bug here must not change a call or lose a finding
            logger.warning("Scan counting failed", error_type=type(exc).__name__)

    def _note_scan(self, job: _Job, findings: Any) -> None:
        if self._counters is None:
            return
        try:
            self._counters.note_scan(job.organization_id, job.kinds, findings)
        except Exception as exc:  # noqa: BLE001  see _note_loss
            logger.warning("Scan counting failed", error_type=type(exc).__name__)

    @property
    def counters(self) -> ScanCounters | None:
        return self._counters

    def flush_counts(self) -> None:
        """Sends what has been counted since the last report, in pieces core accepts. Never raises, never blocks."""
        if self._counters is None or self._counts_dispatcher is None:
            return
        self._last_flush = self._clock()
        try:
            items = self._counters.drain()
            for start in range(0, len(items), COUNTS_ITEMS_PER_REPORT):
                chunk = items[start:start + COUNTS_ITEMS_PER_REPORT]
                report = ScanCountsReport(uuid4(), self._fingerprint, tuple(chunk))
                if not self._counts_dispatcher.submit(report):
                    self._counters.restore(chunk)
        except Exception as exc:  # noqa: BLE001  counting is evidence, never enforcement: it must not take the scanner down
            logger.warning("Scan counts flush failed", error_type=type(exc).__name__)

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self._counts_flush_seconds)
            self.flush_counts()

    def _restore_counts(self, report: ScanCountsReport) -> None:
        if self._counters is not None:
            self._counters.restore(list(report.items))

    def _count_counts_report(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_radar_counts_report(outcome)

    # -- metrics --------------------------------------------------------------------------------------------
    def _count_scan(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_radar_scan(outcome)

    def _count_report(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_radar_report(outcome)

    def _observe_duration(self, ms: float) -> None:
        if self._metrics is not None:
            self._metrics.record_radar_duration(ms)
