"""
Shared machinery for the gateway's non-blocking reports to core (trips, tool observations, and later findings).

A report must never delay or break enforcement. `submit()` is synchronous and does no I/O: it starts a background task that
sends with retries and backoff. Past the in-flight limit the newest report is dropped and counted (the caller decides whether
it can try again later). A reporter answers "ok", "drop" (retrying cannot help, for example core refused the claim) or "retry".
Nothing here knows what a report contains.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Generic, Literal, TypeVar

import structlog

logger = structlog.get_logger(__name__)

SHUTDOWN_WAIT_SECONDS = 3.0

Outcome = Literal["ok", "drop", "retry"]

T = TypeVar("T")


def outcome_for_status(status_code: int) -> Outcome:
    """How a core answer maps to a delivery outcome: success, a refusal retrying cannot fix, or something worth retrying."""
    if status_code == 200:
        return "ok"
    return "drop" if 400 <= status_code < 500 and status_code != 429 else "retry"


class ReportDispatcher(Generic[T]):
    def __init__(
        self,
        *,
        name: str,
        send: Callable[[T], Awaitable[Outcome]],
        count: Callable[[str], None],
        retry_delays: tuple[float, ...],
        max_in_flight: Callable[[], int],
        on_failed: Callable[[T], None] | None = None,
    ) -> None:
        self._name = name
        self._send = send
        self._count = count
        self._delays = retry_delays
        self._max_in_flight = max_in_flight  # read on every submit, so a limit can be changed while running
        self._on_failed = on_failed
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def tasks(self) -> set[asyncio.Task[None]]:
        return self._tasks

    def submit(self, item: T) -> bool:
        """Never raises, never blocks. Returns False (after counting "dropped") when the report was not started."""
        if len(self._tasks) >= self._max_in_flight():
            self._count("dropped")
            logger.warning("Report dropped: too many in flight", report=self._name)
            return False
        try:
            task = asyncio.get_running_loop().create_task(self._deliver(item))
        except RuntimeError:
            self._count("dropped")  # no running loop: only possible outside a request, never in the gateway
            return False
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return True

    async def _deliver(self, item: T) -> None:
        for attempt in range(len(self._delays) + 1):
            try:
                outcome = await self._send(item)
            except Exception as exc:  # noqa: BLE001  a reporter must never take the gateway down
                logger.warning("Report failed", report=self._name, error_type=type(exc).__name__)
                outcome = "retry"
            if outcome == "ok":
                self._count("ok")
                return
            if outcome == "drop":
                self._count("refused")
                return
            if attempt < len(self._delays):
                await asyncio.sleep(self._delays[attempt])
        if self._on_failed is not None:
            self._on_failed(item)
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
