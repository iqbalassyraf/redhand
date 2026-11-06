"""
Reporting a trip (a honeytoken or a decoy tool was touched) to core, promptly and without ever blocking or
breaking enforcement (Phase 3 M3). `report()` is synchronous and does no I/O: it starts a background task that
posts to core with a short timeout and retries with backoff. A 4xx answer is dropped (retrying cannot fix a
claim core refuses); a 5xx or a network error is retried. Core decides what happens next (alert, freeze) from
what it has stored, so this carries only identifiers.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import UUID

import httpx
import structlog

from .metrics import GatewayMetrics

logger = structlog.get_logger(__name__)

MAX_IN_FLIGHT = 50
RETRY_DELAYS = (0.5, 1.0, 2.0, 4.0)  # five attempts in all, about 8 s: inside the 10 s alert target
SHUTDOWN_WAIT_SECONDS = 3.0

Outcome = Literal["ok", "drop", "retry"]


@dataclass(frozen=True, slots=True)
class Trip:
    organization_id: UUID
    trip_id: UUID
    agent_id: UUID
    kind: Literal["honeytoken", "honey_tool"]
    ref_id: UUID
    seen_in: Literal["arguments", "result", "call"]
    tool_name: str
    server: str


class TripReporter(Protocol):
    async def send(self, trip: Trip) -> Outcome: ...


class HttpTripReporter:
    def __init__(self, *, core_url: str, service_token: str | None, http_client: httpx.AsyncClient | None = None) -> None:
        self._url = core_url.rstrip("/") + "/internal/v1/trips"
        self._token = service_token
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(3.0, connect=1.0))

    async def send(self, trip: Trip) -> Outcome:
        if not self._token:
            return "drop"  # nothing can ever be delivered without the token; the metric makes that visible
        try:
            response = await self._http.post(
                self._url,
                json={
                    "organization_id": str(trip.organization_id), "trip_id": str(trip.trip_id),
                    "agent_id": str(trip.agent_id), "kind": trip.kind, "ref_id": str(trip.ref_id),
                    "seen_in": trip.seen_in, "tool_name": trip.tool_name[:128], "server": trip.server[:128],
                },
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            logger.warning("Trip report failed: core unreachable", error_type=type(exc).__name__)
            return "retry"
        if response.status_code == 200:
            return "ok"
        logger.warning("Trip report refused", status=response.status_code)
        return "drop" if 400 <= response.status_code < 500 and response.status_code != 429 else "retry"


class TripDispatcher:
    def __init__(
        self, *, reporter: TripReporter, metrics: GatewayMetrics | None = None,
        retry_delays: tuple[float, ...] = RETRY_DELAYS,
    ) -> None:
        self._reporter = reporter
        self._metrics = metrics
        self._delays = retry_delays
        self._tasks: set[asyncio.Task[None]] = set()

    def report(self, trip: Trip) -> None:
        """Never raises, never blocks. Past 50 reports in flight the newest is dropped and counted."""
        if len(self._tasks) >= MAX_IN_FLIGHT:
            self._count("dropped")
            logger.warning("Trip report dropped: too many in flight")
            return
        try:
            task = asyncio.get_running_loop().create_task(self._deliver(trip))
        except RuntimeError:
            self._count("dropped")  # no running loop: only possible outside a request, never in the gateway
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _deliver(self, trip: Trip) -> None:
        for attempt in range(len(self._delays) + 1):
            try:
                outcome = await self._reporter.send(trip)
            except Exception as exc:  # noqa: BLE001  a reporter must never take the gateway down
                logger.warning("Trip report failed", error_type=type(exc).__name__)
                outcome = "retry"
            if outcome == "ok":
                self._count("ok")
                return
            if outcome == "drop":
                self._count("refused")
                return
            if attempt < len(self._delays):
                await asyncio.sleep(self._delays[attempt])
        self._count("failed")

    async def wait_idle(self) -> None:
        """Waits until every pending report has finished (used by tests and by shutdown)."""
        while self._tasks:
            await asyncio.wait(list(self._tasks))

    async def aclose(self, timeout: float = SHUTDOWN_WAIT_SECONDS) -> None:
        """Gives pending reports a few seconds on shutdown, then cancels what is left."""
        pending = list(self._tasks)
        if not pending:
            return
        _, still = await asyncio.wait(pending, timeout=timeout)
        for task in still:
            task.cancel()

    def _count(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_trip_report(outcome)
