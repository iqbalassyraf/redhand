"""
Reporting the model proxy's usage to core (Phase 4.5 B5b, ADR 0025).

The proxy records, for every call, what the PROVIDER counted (input and output tokens). `record()` only adds to a small in-memory table and never blocks or raises, so reporting can never
slow down or break a call (CLAUDE.md 4.7). A background flush sends the table to core's `POST /internal/v1/model-usage` in batches of at most 100 aggregates, each with its own id, so a
batch core already has is recognised and counted once. A batch that fails is retried with the SAME id and the SAME items (after a growing, jittered wait); while core is down new usage
keeps adding up in memory, bounded by `max_keys` (overflow is dropped and counted, never blocks). A batch core refuses for good (a 4xx other than 408 or 429) is dropped and counted: retrying cannot fix it.

Only counts and model names are sent: no prompt, no completion, no organization (core takes the tenant from the agent's own row), no token or key. Usage that cannot be priced is not hidden:
a call the provider gave no usage for is counted in `calls_without_usage`, never as free.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import Counter, deque
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
import structlog

logger = structlog.get_logger("agentwall.model_usage")

MAX_ITEMS_PER_BATCH = 100  # core accepts 500; a smaller batch keeps one slow request small
MAX_BACKOFF_SECONDS = 60.0
MAX_BACKOFF_EXPONENT = 10  # capped before use: an unbounded 2**failures overflows a float after about a thousand failures
REPORT_TIMEOUT_SECONDS = 5.0
MAX_TOKENS = 10**12  # the same ceiling core enforces; a larger count is clamped here so one hostile answer cannot poison a batch
MAX_MODEL_LENGTH = 128

# Outcomes that used the provider: a call, with whatever the provider reported. Everything else (refusals before the provider, provider errors) used nothing.
COUNTED_OUTCOMES = frozenset({"ok", "usage_not_reported", "stream_interrupted", "stream_too_large", "stream_cancelled"})
PROVIDER = "anthropic"

RETRYABLE_STATUSES = frozenset({408, 429})


class ReportingUsageSink:
    def __init__(
        self,
        *,
        core_url: str,
        service_token: str | None,
        http_client: httpx.AsyncClient | None = None,
        flush_interval: float = 5.0,
        max_keys: int = 5_000,
        clock: Callable[[], float] = time.monotonic,
        jitter: Callable[[], float] = random.random,
        wall_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._url = core_url.rstrip("/") + "/internal/v1/model-usage"
        self._token = service_token
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(REPORT_TIMEOUT_SECONDS, connect=2.0))
        self._interval = flush_interval
        self._max_keys = max_keys
        self._clock = clock
        self._jitter = jitter
        self._wall = wall_clock or (lambda: datetime.now(timezone.utc))
        # (agent id, model) -> [calls, input tokens, output tokens, calls without usage, first seen (ISO)]
        self._pending: dict[tuple[str, str], list[Any]] = {}
        self._retry: deque[tuple[str, list[dict[str, Any]]]] = deque()  # at most one entry: the flush stops at the first failure
        self._failures = 0
        self._next_flush_at = 0.0
        self._flushing = False
        self._loop_task: asyncio.Task[None] | None = None
        self.stats: Counter[str] = Counter()

    # --- recording: synchronous, in memory, never raises -------------------------------------------------------------------------------

    def record(self, usage: Any) -> None:
        if self._token is None:
            self.stats["dropped_not_configured"] += 1
            return
        if usage.outcome not in COUNTED_OUTCOMES:
            return
        model = str(usage.model).strip().lower()[:MAX_MODEL_LENGTH]
        if not model:
            return
        inp = min(max(int(usage.input_tokens), 0), MAX_TOKENS)
        out = min(max(int(usage.output_tokens), 0), MAX_TOKENS)
        key = (str(usage.agent_id), model)
        entry = self._pending.get(key)
        if entry is None:
            if len(self._pending) >= self._max_keys:
                self.stats["dropped_overflow"] += 1
                return
            entry = [0, 0, 0, 0, self._wall().isoformat()]
            self._pending[key] = entry
        entry[0] += 1
        entry[1] = min(entry[1] + inp, MAX_TOKENS)
        entry[2] = min(entry[2] + out, MAX_TOKENS)
        if inp == 0 and out == 0:
            entry[3] += 1  # the provider reported nothing for this call: counted apart, never as free
        self.stats["recorded"] += 1

    def pending_snapshot(self) -> list[dict[str, Any]]:
        return [self._item(key, entry) for key, entry in self._pending.items()]

    def retry_depth(self) -> int:
        return len(self._retry)

    @staticmethod
    def _item(key: tuple[str, str], entry: list[Any]) -> dict[str, Any]:
        return {
            "agent_id": key[0], "provider": PROVIDER, "model": key[1], "calls": entry[0], "input_tokens": entry[1], "output_tokens": entry[2],
            "calls_without_usage": entry[3], "occurred_at": entry[4],
        }

    # --- flushing ----------------------------------------------------------------------------------------------------------------------

    def next_flush_delay(self) -> float:
        return max(0.0, self._next_flush_at - self._clock())

    async def flush_if_due(self) -> bool:
        if self._clock() < self._next_flush_at:
            return True
        return await self.flush()

    async def flush(self) -> bool:
        """Sends the batch that failed last time (same id, same items), then everything pending. Stops at the first failure. Never raises; True when nothing is left to send."""
        if self._flushing:
            return False
        self._flushing = True
        try:
            while True:
                if self._retry:
                    batch_id, items = self._retry[0]
                elif self._pending:
                    batch_id, items = str(uuid4()), self._take_batch()
                else:
                    self._after_flush(True)
                    return True
                verdict = await self._send(batch_id, items)
                if verdict == "retry":
                    if not self._retry:
                        self._retry.append((batch_id, items))
                    self.stats["failed_batches"] += 1
                    self._after_flush(False)
                    return False
                if self._retry:
                    self._retry.popleft()
                if verdict == "ok":
                    self.stats["reported_batches"] += 1
                else:
                    self.stats["dropped_refused"] += 1
        finally:
            self._flushing = False

    def _take_batch(self) -> list[dict[str, Any]]:
        keys = list(self._pending)[:MAX_ITEMS_PER_BATCH]
        return [self._item(key, self._pending.pop(key)) for key in keys]

    async def _send(self, batch_id: str, items: list[dict[str, Any]]) -> str:
        """"ok", "retry" (try the same batch again later) or "refused" (core will never accept it: drop)."""
        try:
            response = await self._http.post(self._url, json={"batch_id": batch_id, "items": items}, headers={"Authorization": f"Bearer {self._token}"})
        except httpx.HTTPError as exc:
            logger.warning("Model usage report failed: core unreachable", error_type=type(exc).__name__)
            return "retry"
        status = response.status_code
        if 200 <= status < 300:
            return "ok"
        if status in RETRYABLE_STATUSES or status >= 500:
            logger.warning("Model usage report failed: core answered", status=status)
            return "retry"
        logger.error("Model usage batch refused by core and dropped", status=status, items=len(items))
        return "refused"

    def _after_flush(self, ok: bool) -> None:
        now = self._clock()
        if ok:
            self._failures = 0
            self._next_flush_at = now + self._interval
            return
        self._failures += 1
        backoff = min(MAX_BACKOFF_SECONDS, self._interval * (2 ** min(self._failures, MAX_BACKOFF_EXPONENT)))
        self._next_flush_at = now + backoff * (0.5 + self._jitter() / 2)

    # --- lifecycle ---------------------------------------------------------------------------------------------------------------------

    def start(self) -> None:
        if self._loop_task is None and self._token is not None:
            self._loop_task = asyncio.get_running_loop().create_task(self._run())

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            await self.flush_if_due()

    async def stop(self) -> None:
        if self._loop_task is not None:
            self._loop_task.cancel()
            self._loop_task = None
        if self._token is not None:
            await asyncio.wait_for(self.flush(), timeout=REPORT_TIMEOUT_SECONDS + 1)  # one last best-effort report on shutdown

    # --- metrics -----------------------------------------------------------------------------------------------------------------------

    def render_prometheus(self) -> str:
        lines = [
            "# TYPE agentwall_model_usage_reported_batches_total counter",
            f"agentwall_model_usage_reported_batches_total {self.stats['reported_batches']}",
            "# TYPE agentwall_model_usage_failed_batches_total counter",
            f"agentwall_model_usage_failed_batches_total {self.stats['failed_batches']}",
            "# TYPE agentwall_model_usage_dropped_total counter",
        ]
        for reason in ("overflow", "refused", "not_configured"):
            lines.append(f'agentwall_model_usage_dropped_total{{reason="{reason}"}} {self.stats["dropped_" + reason]}')
        return "\n".join(lines) + "\n"
