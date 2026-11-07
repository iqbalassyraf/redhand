"""
Reporting a trip (a honeytoken or a decoy tool was touched) to core, promptly and without ever blocking or
breaking enforcement (Phase 3 M3). `report()` is synchronous and does no I/O: it starts a background task that
posts to core with a short timeout and retries with backoff. A 4xx answer is dropped (retrying cannot fix a
claim core refuses); a 5xx or a network error is retried. Core decides what happens next (alert, freeze) from
what it has stored, so this carries only identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol
from uuid import UUID

import httpx
import structlog

from .dispatch import SHUTDOWN_WAIT_SECONDS, Outcome, ReportDispatcher, outcome_for_status
from .metrics import GatewayMetrics

logger = structlog.get_logger(__name__)

MAX_IN_FLIGHT = 50
RETRY_DELAYS = (0.5, 1.0, 2.0, 4.0)  # five attempts in all, about 8 s: inside the 10 s alert target

__all__ = ["MAX_IN_FLIGHT", "Outcome", "RETRY_DELAYS", "Trip", "TripDispatcher", "TripReporter", "HttpTripReporter"]


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
        if response.status_code != 200:
            logger.warning("Trip report refused", status=response.status_code)
        return outcome_for_status(response.status_code)


class TripDispatcher:
    def __init__(
        self, *, reporter: TripReporter, metrics: GatewayMetrics | None = None,
        retry_delays: tuple[float, ...] = RETRY_DELAYS,
    ) -> None:
        self._reporter = reporter
        self._metrics = metrics
        self._dispatcher: ReportDispatcher[Trip] = ReportDispatcher(
            name="trip", send=lambda trip: self._reporter.send(trip), count=self._count, retry_delays=retry_delays,
            max_in_flight=lambda: MAX_IN_FLIGHT,
        )

    @property
    def _tasks(self) -> set[Any]:
        return self._dispatcher.tasks

    def report(self, trip: Trip) -> None:
        """Never raises, never blocks. Past 50 reports in flight the newest is dropped and counted."""
        self._dispatcher.submit(trip)

    async def wait_idle(self) -> None:
        """Waits until every pending report has finished (used by tests and by shutdown)."""
        await self._dispatcher.wait_idle()

    async def aclose(self, timeout: float = SHUTDOWN_WAIT_SECONDS) -> None:
        """Gives pending reports a few seconds on shutdown, then cancels what is left."""
        await self._dispatcher.aclose(timeout)

    def _count(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_trip_report(outcome)
