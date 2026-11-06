"""
Black Box Recorder (Phase 3, M1): buffers the gateway's own decisions and reports them to core in
small batches. See docs/plans/phase3-plan.md and services/redhand-core/src/redhand_core/routers/events.py
(the receiver).

Design rules this module keeps, mirroring budget.py:
- `record()` is synchronous and does no I/O: it only appends to a bounded in-memory deque, so it can
  never add latency or block the call it is recording.
- The buffer is bounded. When full, the NEWEST event is dropped (not the oldest, so older history is
  not thrown away for events still arriving) and a counter is incremented. The next successful batch
  for that organization carries one synthetic `recorder.gap` event noting how many were lost.
- One batch is one organization (core's chain is per organization): the buffer is grouped by
  organization_id, and a flush sends one HTTP call per organization that has buffered events.
- A single tracked flush task is shared by the callers that start one (the same pattern as BudgetMeter),
  and `flush()` itself holds a lock, so a flush started any other way (the background loop, shutdown)
  waits for the one in flight instead of sending the same buffered events a second time.
- A batch keeps its id and its exact items until core acknowledges it. Core ignores a batch id it has
  already stored, so a retry after a lost reply is harmless only if it carries the SAME id and items;
  a fresh id would store the events twice. Events that arrive meanwhile go in the next batch.
- Losing the recorder (core down, or the process crashing) never affects enforcement: nothing here
  is on the decision path, and every method that can fail swallows its own exceptions.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import random
import time
from typing import Any, Protocol
from uuid import UUID, uuid4

import httpx
import structlog

from .metrics import GatewayMetrics

logger = structlog.get_logger(__name__)

MAX_BACKOFF_SECONDS = 60.0
MAX_BACKOFF_EXPONENT = 10
REPORT_TIMEOUT_SECONDS = 5.0
URGENT_WAIT_SECONDS = 1.0


@dataclass(slots=True)
class _Batch:
    """A batch sent to core and not yet acknowledged: resent unchanged (same id, same items) until it is."""

    batch_id: str
    items: list[dict[str, Any]]
    events: int  # buffered events included (the gap marker, if any, is not counted)
    dropped: int  # drops the gap marker reported


@dataclass(frozen=True, slots=True)
class GatewayEvent:
    """One decision the gateway made. Mirrors redhand_core.blackbox.models.GatewayEventItem."""

    agent_id: UUID
    organization_id: UUID
    occurred_at: str  # ISO-8601 UTC; the gateway's own clock
    server: str
    method: str
    tool_name: str
    decision: str  # "ALLOW" | "BLOCK" | "ERROR"
    reasons: list[str] = field(default_factory=list)
    upstream_status: int | None = None
    latency_ms: float | None = None
    argument_keys: list[str] = field(default_factory=list)
    arguments_sha256: str = ""
    result_size_bytes: int | None = None
    redaction_count: int = 0
    credential_jti: str | None = None
    # Redacted, size-capped excerpts (agentwall/src/gateway/capture.py); None unless the organization turned
    # payload capture on. Core stores them only if its own flag is on too.
    arguments_redacted: dict[str, Any] | None = None
    result_excerpt: dict[str, Any] | None = None

    def as_item(self) -> dict[str, Any]:
        return {
            "agent_id": str(self.agent_id), "occurred_at": self.occurred_at, "gateway_instance": "",
            "server": self.server, "method": self.method, "tool_name": self.tool_name,
            "decision": self.decision, "reasons": self.reasons, "upstream_status": self.upstream_status,
            "latency_ms": self.latency_ms, "argument_keys": self.argument_keys,
            "arguments_sha256": self.arguments_sha256, "result_size_bytes": self.result_size_bytes,
            "redaction_count": self.redaction_count, "credential_jti": self.credential_jti,
            "arguments_redacted": self.arguments_redacted, "result_excerpt": self.result_excerpt,
        }


class EventReporter(Protocol):
    async def send(self, instance_id: str, batch_id: str, organization_id: UUID, items: list[dict[str, Any]]) -> bool:
        """True only when core accepted the batch."""
        ...


class HttpEventReporter:
    def __init__(
        self,
        *,
        core_url: str,
        service_token: str | None,
        http_client: httpx.AsyncClient | None = None,
        metrics: GatewayMetrics | None = None,
    ) -> None:
        self._url = core_url.rstrip("/") + "/internal/v1/events"
        self._token = service_token
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(REPORT_TIMEOUT_SECONDS, connect=2.0))
        self._metrics = metrics

    async def send(self, instance_id: str, batch_id: str, organization_id: UUID, items: list[dict[str, Any]]) -> bool:
        if not self._token:
            return False
        try:
            response = await self._http.post(
                self._url,
                json={
                    "instance_id": instance_id, "batch_id": batch_id,
                    "organization_id": str(organization_id), "items": items,
                },
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            logger.warning("Event report failed: core unreachable", error_type=type(exc).__name__)
            return False
        if response.status_code != 200:
            logger.warning("Event report refused", status=response.status_code)
            return False
        self._note_rejections(response)
        return True

    def _note_rejections(self, response: httpx.Response) -> None:
        """Core acknowledges a batch even when it refuses to store some items (wrong tenant, invalid
        field, or a database fault). Those items are not retried, since resending cannot fix them, so
        they must at least be visible: one such fault once dropped every event silently."""
        try:
            body = response.json()
            rejected = int(body["rejected"])
            accepted = int(body["accepted"])
        except (ValueError, KeyError, TypeError):
            logger.warning("Event report acknowledged with an unreadable body")
            return
        if rejected > 0:
            logger.warning("Event batch partly rejected by core", accepted=accepted, rejected=rejected)
            if self._metrics is not None:
                self._metrics.record_events_rejected(rejected)


class EventRecorder:
    def __init__(
        self,
        *,
        instance_id: str,
        reporter: EventReporter,
        flush_interval: float = 2.0,
        max_buffered: int = 10_000,
        max_batch_size: int = 500,
        metrics: GatewayMetrics | None = None,
    ) -> None:
        self.instance_id = instance_id
        self._reporter = reporter
        self._interval = flush_interval
        self._max_buffered = max_buffered
        self._max_batch_size = max_batch_size
        self._metrics = metrics
        self._buffers: dict[UUID, deque[GatewayEvent]] = {}
        self._dropped: dict[UUID, int] = {}
        self._dropped_agent: dict[UUID, UUID] = {}  # an agent of the org, so the gap marker itself is a valid event
        self._failures = 0
        self._next_flush_at = 0.0
        self._flush_task: asyncio.Task[bool] | None = None
        self._flush_lock = asyncio.Lock()
        self._inflight: dict[UUID, _Batch] = {}
        self._loop_task: asyncio.Task[None] | None = None

    # -- the recording path: synchronous, no I/O ------------------------------------------------
    def record(self, event: GatewayEvent) -> None:
        buf = self._buffers.setdefault(event.organization_id, deque())
        total_buffered = sum(len(b) for b in self._buffers.values())
        if total_buffered >= self._max_buffered:
            self._dropped[event.organization_id] = self._dropped.get(event.organization_id, 0) + 1
            self._dropped_agent[event.organization_id] = event.agent_id
            if self._metrics is not None:
                self._metrics.record_event_dropped()
            return
        buf.append(event)

    @property
    def buffered_count(self) -> int:
        return sum(len(b) for b in self._buffers.values())

    # -- reporting to core -----------------------------------------------------------------------
    def schedule_flush_if_due(self) -> None:
        if self.buffered_count and not self._flush_in_flight() and time.monotonic() >= self._next_flush_at:
            self._start_flush()

    async def flush_now(self, timeout: float = URGENT_WAIT_SECONDS) -> None:
        """Flushes immediately and waits up to `timeout`; a flush still running after that carries on
        in the background. Used when a caller cannot wait for the next scheduled flush (e.g. a trip
        in a later phase); M1 calls this only on shutdown, with a longer timeout."""
        deadline = asyncio.get_running_loop().time() + timeout
        try:
            if not self.buffered_count:
                return
            task = self._start_flush()
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return
            await asyncio.wait_for(asyncio.shield(task), remaining)
        except asyncio.TimeoutError:
            return
        except Exception as exc:  # noqa: BLE001  never break the caller
            logger.warning("Urgent event flush failed", error_type=type(exc).__name__)

    def _flush_in_flight(self) -> bool:
        return self._flush_task is not None and not self._flush_task.done()

    def _start_flush(self) -> asyncio.Task[bool]:
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.get_running_loop().create_task(self.flush())
        return self._flush_task

    async def flush(self) -> bool:
        """Sends every organization's buffered events, each as one or more batches of at most
        `max_batch_size`. Never raises. Returns True if every batch sent was accepted. Callers are
        serialised: a flush that arrives while another is running waits, then sees what is left."""
        async with self._flush_lock:
            orgs = [org for org, buf in self._buffers.items() if buf or self._dropped.get(org)]
            if not orgs:
                return True
            all_ok = True
            for org in orgs:
                if not await self._flush_org(org):
                    all_ok = False
            self._after_flush(all_ok)
            return all_ok

    def _next_batch(self, org: UUID, buf: deque[GatewayEvent]) -> _Batch | None:
        items: list[dict[str, Any]] = []
        dropped = self._dropped.get(org, 0)
        dropped_agent = self._dropped_agent.get(org)
        reported_drops = 0
        if dropped and dropped_agent is not None:
            # The gap marker must itself be a valid, storable event: core's record_events() checks
            # every item's agent_id against the agents table, so this uses an agent of the org that
            # actually had a drop rather than a synthetic id that would just be rejected.
            reported_drops = dropped
            items.append({
                "agent_id": str(dropped_agent), "occurred_at": _now_iso(), "gateway_instance": self.instance_id,
                "server": "", "method": "recorder.gap", "tool_name": "", "decision": "ERROR",
                "reasons": [f"{dropped} event(s) dropped: the recorder buffer was full"],
                "upstream_status": None, "latency_ms": None, "argument_keys": [], "arguments_sha256": "",
                "result_size_bytes": None, "redaction_count": 0, "credential_jti": None,
            })
        pending = list(buf)[: self._max_batch_size - len(items)]
        for event in pending:
            item = event.as_item()
            item["gateway_instance"] = self.instance_id
            items.append(item)
        if not items:
            return None
        return _Batch(uuid4().hex, items, len(pending), reported_drops)

    async def _flush_org(self, org: UUID) -> bool:
        buf = self._buffers.get(org)
        if buf is None:
            return True
        batch = self._inflight.get(org)
        if batch is None:
            batch = self._next_batch(org, buf)
            if batch is None:
                return True
            self._inflight[org] = batch
        try:
            accepted = await self._reporter.send(self.instance_id, batch.batch_id, org, batch.items)
        except Exception as exc:  # noqa: BLE001  a reporter must never take the gateway down
            logger.warning("Event report failed", error_type=type(exc).__name__)
            accepted = False
        if accepted:
            del self._inflight[org]
            # Only this method removes from the buffer's head (record() only appends), so the first
            # `batch.events` events are exactly the ones just acknowledged.
            for _ in range(batch.events):
                buf.popleft()
            if batch.dropped:
                remaining = self._dropped.get(org, 0) - batch.dropped
                if remaining > 0:
                    self._dropped[org] = remaining  # more were dropped while this batch was in flight
                else:
                    self._dropped.pop(org, None)
                    self._dropped_agent.pop(org, None)
            if not buf and not self._dropped.get(org):
                del self._buffers[org]
        return accepted

    def _after_flush(self, ok: bool) -> None:
        now = time.monotonic()
        if ok:
            self._failures = 0
            self._next_flush_at = now + self._interval
        else:
            self._failures += 1
            backoff = min(MAX_BACKOFF_SECONDS, self._interval * (2 ** min(self._failures, MAX_BACKOFF_EXPONENT)))
            self._next_flush_at = now + backoff * (0.5 + random.random() / 2)
        if self._metrics is not None:
            self._metrics.record_event_flush("ok" if ok else "failed", self.buffered_count)

    # -- lifecycle ---------------------------------------------------------------------------------
    def start(self) -> None:
        if self._loop_task is None:
            self._loop_task = asyncio.get_running_loop().create_task(self._run())

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            if self.buffered_count and time.monotonic() >= self._next_flush_at:
                await self.flush()

    async def stop(self, timeout: float = REPORT_TIMEOUT_SECONDS) -> None:
        if self._loop_task is not None:
            self._loop_task.cancel()
            self._loop_task = None
        try:
            await asyncio.wait_for(self.flush(), timeout)
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            logger.warning("Final event flush did not complete", buffered=self.buffered_count)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
