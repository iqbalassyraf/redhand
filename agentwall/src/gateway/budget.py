"""
Budget Guard in the gateway: a per-agent, per-day counter of forwarded tool calls.
See docs/adr/0010-budget-guard.md and docs/plans/phase2-m3-budget-guard.md.

What it counts: tool calls the gateway forwards upstream. Calls refused for any reason do not count,
so an agent that is being refused cannot burn its own limit. RedHand sees calls through the gateway,
not LLM tokens or money.

Design rules this module keeps:
- The decision path (`try_consume`) is synchronous and does no I/O: the check and the increment are one
  step with no `await` between them, so concurrent calls on the event loop cannot overshoot a limit.
- Effective usage = usage reported by OTHER gateway instances (from core's context, at most 2 s old)
  + this instance's own local total (always exact). With one instance the count is exact.
- Totals are reported to core as CUMULATIVE numbers, so resending is harmless and no queue can grow.
  A crash loses at most the last few seconds of this instance's own calls (an undercount).
- Fail closed: if a limited agent cannot be tracked (the table is full), the call is refused.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timedelta
import random
import time
from typing import Any, Protocol
from uuid import UUID

import httpx
import structlog

from .metrics import GatewayMetrics

logger = structlog.get_logger(__name__)

WARN_PERCENT = 80
MAX_ITEMS_PER_REPORT = 1000  # core accepts at most this many items per report
REPORT_TIMEOUT_SECONDS = 5.0
URGENT_WAIT_SECONDS = 1.0  # how long a call that crosses 80% or 100% may wait for its report
MAX_BACKOFF_SECONDS = 60.0
MAX_BACKOFF_EXPONENT = 10
KEEP_DAYS = 2  # counters older than this (relative to the newest day seen) are dropped once reported

Key = tuple[UUID, str]


@dataclass(frozen=True, slots=True)
class BudgetState:
    """What core tells the gateway about one agent's budget (see GatewayBudgetContext in core)."""

    daily_call_limit: int | None
    used_by_other_instances: int
    day_key: str
    resets_at: datetime


@dataclass(frozen=True, slots=True)
class BudgetDecision:
    allowed: bool
    used: int  # effective usage: including this call when allowed, before it when refused
    limit: int | None
    reason: str = "ok"  # ok | limit | meter_full
    urgent: bool = False  # the call crossed 80% or 100%: report to core now


class UsageReporter(Protocol):
    async def send(self, instance_id: str, items: list[dict[str, Any]]) -> bool:
        """Reports cumulative totals. True only when core accepted them."""
        ...


class HttpUsageReporter:
    def __init__(self, *, core_url: str, service_token: str | None, http_client: httpx.AsyncClient | None = None) -> None:
        self._url = core_url.rstrip("/") + "/internal/v1/usage"
        self._token = service_token
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(REPORT_TIMEOUT_SECONDS, connect=2.0))

    async def send(self, instance_id: str, items: list[dict[str, Any]]) -> bool:
        if not self._token:
            return False
        try:
            response = await self._http.post(
                self._url,
                json={"instance_id": instance_id, "items": items},
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            logger.warning("Usage report failed: core unreachable", error_type=type(exc).__name__)
            return False
        if response.status_code != 200:
            logger.warning("Usage report refused", status=response.status_code)
            return False
        return True


class BudgetMeter:
    def __init__(
        self,
        *,
        instance_id: str,
        reporter: UsageReporter,
        flush_interval: float = 5.0,
        max_keys: int = 100_000,
        clock: Callable[[], float] = time.monotonic,
        jitter: Callable[[], float] = random.random,
        metrics: GatewayMetrics | None = None,
    ) -> None:
        self.instance_id = instance_id
        self._reporter = reporter
        self._interval = flush_interval
        self._max_keys = max_keys
        self._clock = clock
        self._jitter = jitter
        self._metrics = metrics
        self._counts: dict[Key, int] = {}  # this instance's cumulative calls per (agent, day)
        self._dirty: set[Key] = set()  # keys with calls not yet acknowledged by core
        self._level: dict[Key, int] = {}  # highest threshold (80 or 100) already reported urgently
        self._flushing = False
        self._failures = 0
        self._next_flush_at = 0.0
        self._flush_task: asyncio.Task[bool] | None = None  # the one report in flight, joined by every caller
        self._loop_task: asyncio.Task[None] | None = None

    # -- the decision path: synchronous, no I/O --------------------------------------------------
    def try_consume(self, agent_id: UUID, state: BudgetState) -> BudgetDecision:
        """Counts one forwarded call if the agent is within its limit; refuses it otherwise."""
        key: Key = (agent_id, state.day_key)
        limit = state.daily_call_limit
        local = self._counts.get(key)
        if local is None:
            if len(self._counts) >= self._max_keys:
                if limit is None:
                    return BudgetDecision(True, state.used_by_other_instances, None)  # nothing to enforce
                return BudgetDecision(False, state.used_by_other_instances, limit, "meter_full")
            local = 0
        effective = state.used_by_other_instances + local
        if limit is not None and effective + 1 > limit:
            return BudgetDecision(False, effective, limit, "limit")

        self._counts[key] = local + 1
        self._dirty.add(key)
        effective += 1
        urgent = False
        if limit is not None:
            level = 100 if effective >= limit else (WARN_PERCENT if effective * 100 >= limit * WARN_PERCENT else 0)
            if level > self._level.get(key, 0):
                self._level[key] = level
                urgent = True
        return BudgetDecision(True, effective, limit, "ok", urgent)

    # -- reporting to core -----------------------------------------------------------------------
    @property
    def unreported_keys(self) -> int:
        return len(self._dirty)

    def schedule_flush_if_due(self) -> None:
        """Starts a report in the background when one is due. Called from inside a request, so the
        report runs while the call is in flight (Cloud Run only gives CPU to instances serving requests)."""
        if self._dirty and not self._report_in_flight() and self._clock() >= self._next_flush_at:
            self._start_report()

    async def flush_now(self, timeout: float = URGENT_WAIT_SECONDS) -> None:
        """
        Reports immediately and waits up to `timeout` in total; a report still running after that carries
        on in the background. If calls arrived while an earlier report was on the wire (so it did not
        include them), one follow-up report is sent for them.
        """
        deadline = asyncio.get_running_loop().time() + timeout
        try:
            for _ in range(2):
                if not self._dirty:
                    return
                task = self._start_report()  # joins the report in flight, or starts one
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    return
                await asyncio.wait_for(asyncio.shield(task), remaining)
        except asyncio.TimeoutError:
            return  # expected: the report carries on in the background
        except Exception as exc:  # noqa: BLE001  never break the call that asked, but leave a trace
            logger.warning("Urgent usage report failed", error_type=type(exc).__name__)

    def _report_in_flight(self) -> bool:
        return self._flush_task is not None and not self._flush_task.done()

    def _start_report(self) -> asyncio.Task[bool]:
        """The single report task: callers join it instead of racing a second one."""
        if self._flush_task is None or self._flush_task.done():
            task = asyncio.get_running_loop().create_task(self.flush())
            self._flush_task = task
        return self._flush_task

    async def flush(self) -> bool:
        """Sends the cumulative totals of every key that changed. Never raises. Returns True if all were accepted."""
        if self._flushing or not self._dirty:
            return True
        self._flushing = True
        try:
            snapshot = {key: self._counts[key] for key in self._dirty}
            keys = list(snapshot)
            all_ok = True
            for start in range(0, len(keys), MAX_ITEMS_PER_REPORT):
                chunk = keys[start : start + MAX_ITEMS_PER_REPORT]
                items = [{"agent_id": str(a), "day_key": d, "calls": snapshot[(a, d)]} for a, d in chunk]
                try:
                    accepted = await self._reporter.send(self.instance_id, items)
                except Exception as exc:  # noqa: BLE001  a reporter must never take the gateway down
                    logger.warning("Usage report failed", error_type=type(exc).__name__)
                    accepted = False
                if not accepted:
                    all_ok = False
                    break
                for key in chunk:
                    if self._counts.get(key) == snapshot[key]:  # nothing was added while the report was in flight
                        self._dirty.discard(key)
            self._after_flush(all_ok)
            return all_ok
        finally:
            self._flushing = False

    def _after_flush(self, ok: bool) -> None:
        now = self._clock()
        if ok:
            self._failures = 0
            self._next_flush_at = now + self._interval
            self._prune()
        else:
            self._failures += 1
            # The exponent is capped before it is used: an unbounded 2**failures overflows a float after
            # about a thousand failures and would switch the backoff off.
            backoff = min(MAX_BACKOFF_SECONDS, self._interval * (2 ** min(self._failures, MAX_BACKOFF_EXPONENT)))
            self._next_flush_at = now + backoff * (0.5 + self._jitter() / 2)
        if self._metrics is not None:
            self._metrics.record_budget_flush("ok" if ok else "failed", len(self._dirty))

    def _prune(self) -> None:
        """Drops reported counters from days long gone so the table cannot grow without bound."""
        if not self._counts:
            return
        newest = max(day for _, day in self._counts)
        try:
            cutoff = (date.fromisoformat(newest) - timedelta(days=KEEP_DAYS)).isoformat()
        except ValueError:
            return
        for key in [k for k in self._counts if k[1] < cutoff and k not in self._dirty]:
            del self._counts[key]
            self._level.pop(key, None)

    # -- lifecycle -------------------------------------------------------------------------------
    def start(self) -> None:
        """Starts a periodic report loop (a safety net; reports are normally triggered by calls)."""
        if self._loop_task is None:
            self._loop_task = asyncio.get_running_loop().create_task(self._run())

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            if self._dirty and self._clock() >= self._next_flush_at:
                await self.flush()

    async def stop(self, timeout: float = REPORT_TIMEOUT_SECONDS) -> None:
        """Final report on shutdown, so a deliberate stop loses nothing."""
        if self._loop_task is not None:
            self._loop_task.cancel()
            self._loop_task = None
        try:
            await asyncio.wait_for(self.flush(), timeout)
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            logger.warning("Final usage report did not complete", unreported=len(self._dirty))
