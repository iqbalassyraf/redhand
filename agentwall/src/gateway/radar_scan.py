"""
Prompt Injection Radar and output checks in the gateway (Phase 4 M4.3, docs/adr/0015-radar-in-the-gateway.md).

OBSERVE ONLY. A tool result is handed to a bounded background queue after the gateway has already decided what to return;
a worker scans it and reports findings to core. The scan can never change, delay or block a call: `submit()` is synchronous and
does no I/O, a full queue drops the work (counted), and any scanner or network error is counted and swallowed. Block mode does
not exist. A finding never carries the scanned text, only a fixed rule id, family, severity, confidence, place and evasion tags.

Cost: the rules read at most 16 KiB from each end of a result (about 1 ms per KiB); the optional second-stage model adds about
8 ms at most. That work runs on a worker thread, never inline, but it still competes for the same CPU, so it is measured
(scripts/latency_baseline.py) and the model is off unless AGENTWALL_RADAR_MODEL_ENABLED is set.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
import time
from typing import Any, Protocol
from uuid import UUID

import httpx
import structlog

from ..firewall import radar
from ..firewall.injection_model import RULES_AND_MODEL
from .dispatch import SHUTDOWN_WAIT_SECONDS, Outcome, ReportDispatcher, outcome_for_status
from .metrics import GatewayMetrics

logger = structlog.get_logger(__name__)

QUEUE_SIZE = 16  # results waiting for a scan; each is already in memory for its own request, so this bounds the extra hold
MAX_IN_FLIGHT = 20
RETRY_DELAYS = (0.5, 1.0, 2.0, 4.0)
THROTTLE_SECONDS = 30.0  # the same (agent, rule, tool, place) is reported at most this often; core also coalesces
MAX_THROTTLE_KEYS = 20_000
MAX_ITEMS = 20

__all__ = ["FindingsReport", "FindingsReporter", "HttpFindingsReporter", "RadarScanner", "kinds_for"]


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
    ) -> None:
        self._metrics = metrics
        self._detectors = RULES_AND_MODEL if use_model else radar.DEFAULT_DETECTORS
        self._clock = clock
        self._queue: asyncio.Queue[_Job] | None = None
        self._worker: asyncio.Task[None] | None = None
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
            return False
        return True

    def _ensure_worker(self) -> asyncio.Queue[_Job]:
        if self._queue is None:
            self._queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        if self._worker is None or self._worker.done():
            self._worker = asyncio.get_running_loop().create_task(self._run(self._queue))
        return self._queue

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

    async def _handle(self, job: _Job) -> None:
        started = time.perf_counter()
        try:
            report = await asyncio.to_thread(
                radar.scan_result, job.result, radar.ScanContext(tool_names=job.tool_names), job.kinds, self._detectors,
            )
        except Exception as exc:  # noqa: BLE001  see above
            logger.warning("Radar scan failed", error_type=type(exc).__name__)
            self._count_scan("error")
            return
        self._observe_duration((time.perf_counter() - started) * 1000)
        self._count_scan("ok")
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
        if items and not self._dispatcher.submit(FindingsReport(job.organization_id, job.agent_id, tuple(items))):
            for item in items:  # not sent: forget the throttle so the next occurrence is reported
                self._throttle.pop((job.agent_id, item["rule_id"], job.tool, item["place"], job.server), None)

    # -- lifecycle ------------------------------------------------------------------------------------------
    async def wait_idle(self) -> None:
        """Waits until queued scans and their reports are done (tests and shutdown)."""
        if self._queue is not None:
            await self._queue.join()
        await self._dispatcher.wait_idle()

    async def aclose(self, timeout: float = SHUTDOWN_WAIT_SECONDS) -> None:
        if self._worker is not None:
            self._worker.cancel()
        await self._dispatcher.aclose(timeout)

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
