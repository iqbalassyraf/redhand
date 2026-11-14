"""
The limiter behind token exchange, Telegram and exports (H3.3). Same behaviour as before for a key (a sliding window), plus a bound on memory:
a caller who sends a different well-formed key every time used to add an entry to a dict that never shrank.
"""

from __future__ import annotations

from redhand_core.services.rate_limit import SlidingWindowLimiter


def test_a_key_is_limited_inside_its_window_and_free_again_after_it() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60.0)
    assert [limiter.allow("k", 3, now) for now in (0.0, 1.0, 2.0)] == [True, True, True]
    assert limiter.allow("k", 3, 3.0) is False
    assert limiter.allow("k", 3, 59.9) is False
    assert limiter.allow("k", 3, 60.5) is True  # the first event left the window


def test_keys_do_not_share_a_budget() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60.0)
    assert limiter.allow("a", 1, 0.0) is True and limiter.allow("a", 1, 0.1) is False
    assert limiter.allow("b", 1, 0.2) is True


def test_a_flood_of_distinct_keys_cannot_grow_memory_past_the_bound() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60.0, max_keys=1000)
    for n in range(50_000):
        limiter.allow(f"key-{n}", 5, now=float(n) * 0.001)  # all inside one window: nothing has expired
    assert len(limiter._events) <= 1000  # noqa: SLF001


def test_idle_keys_are_dropped_when_the_table_is_full() -> None:
    limiter = SlidingWindowLimiter(window_seconds=10.0, max_keys=100)
    for n in range(100):
        limiter.allow(f"old-{n}", 5, now=0.0)
    assert limiter.allow("fresh", 5, now=1000.0) is True  # every old key has expired and is swept
    assert len(limiter._events) == 1  # noqa: SLF001


def test_a_busy_key_keeps_its_count_while_idle_ones_are_evicted() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60.0, max_keys=50)
    assert limiter.allow("busy", 2, 0.0) and limiter.allow("busy", 2, 0.1)
    for n in range(200):
        limiter.allow(f"noise-{n}", 5, 1.0 + n * 0.01)
        limiter.allow("busy", 2, 1.0 + n * 0.01)  # kept recent, so never the one evicted
    assert limiter.allow("busy", 2, 5.0) is False, "evicting noise must not reset the limit of a key that is being limited"


def test_an_evicted_key_starts_fresh_never_stricter() -> None:
    """Eviction can only forget history, which is the safe direction for a rate limit on a key nobody is using."""
    limiter = SlidingWindowLimiter(window_seconds=60.0, max_keys=2)
    limiter.allow("a", 1, 0.0)
    limiter.allow("b", 1, 0.1)
    limiter.allow("c", 1, 0.2)  # evicts "a", the least recently used
    assert limiter.allow("a", 1, 0.3) is True
