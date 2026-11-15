"""
In-process sliding-window rate limiting (CLAUDE.md section 5.6).

Per instance: while the gateway runs as a single instance (`--max-instances 1`, see docs/runbooks/cloud-run-staging.md) the limit is exact; with N
instances each enforces the limit on its own, so the effective limit is up to N times higher. Moving to a shared store means replacing this one
class, which is why every limit goes through `allow(key, limit, now)`.

Memory is bounded. A caller who sends a different key every time (a fresh well-formed agent key, a new address) used to add an entry to a table
that never shrank. When the table is full, entries whose window has passed are swept; if it is still full, the least recently used key is
dropped. Dropping only forgets history for a key nobody is using, so a key that is actively being limited keeps its count (it is the most
recently used).
"""

from __future__ import annotations

from collections import OrderedDict, deque

DEFAULT_MAX_KEYS = 10_000


class SlidingWindowLimiter:
    def __init__(self, window_seconds: float = 60.0, max_keys: int = DEFAULT_MAX_KEYS) -> None:
        self._window = window_seconds
        self._max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def _sweep(self, now: float) -> None:
        expired = [key for key, events in self._hits.items() if not events or now - events[-1] >= self._window]
        for key in expired:
            del self._hits[key]

    def allow(self, key: str, limit: int, now: float) -> bool:
        events = self._hits.get(key)
        if events is None:
            if len(self._hits) >= self._max_keys:
                self._sweep(now)
                while len(self._hits) >= self._max_keys:
                    self._hits.popitem(last=False)
            events = self._hits[key] = deque()
        else:
            self._hits.move_to_end(key)
        while events and now - events[0] >= self._window:
            events.popleft()
        if len(events) >= limit:
            return False
        events.append(now)
        return True
