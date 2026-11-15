"""
Loop meter (Phase 4 M6): counts identical tool calls per agent so a loop can be flagged or throttled.
See docs/plans/phase4-m6-loop-detection.md and docs/adr/0017-loop-detection.md.

What "identical" means: the same agent, the same tool name and the same arguments (key order does not matter). The arguments are
hashed with a per-process random salt, so a digest means nothing outside this process, is never sent or stored anywhere, and the
arguments themselves are never kept.

Design rules this module keeps (the same shape as budget.py):
- Synchronous, no I/O, no await: the check and the count are one step, so concurrent calls on the event loop cannot race.
- Bounded memory whatever an agent sends: each key holds three numbers (a two-bucket sliding-window counter), an agent holds at
  most `max_keys_per_agent` keys, and the whole table at most `max_keys`. Dropping a key forgets a count: a loop may then be missed.
  That is a detection control, not an authorization one, so it errs toward under-counting and is counted in `evictions`.
- Approximate with several gateway instances: each keeps its own table, so the effective limit is the limit times the instances.
- A caller that cannot hash the arguments gets `untracked` and nothing is stored.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import json
import os
import time
from typing import Any, Literal
from uuid import UUID

MAX_HASHED_BYTES = 64 * 1024  # longer arguments are hashed on their first 64 KiB plus their length
DEFAULT_MAX_KEYS_PER_AGENT = 16
DEFAULT_MAX_KEYS = 100_000
DIGEST_BYTES = 16

Outcome = Literal["ok", "flagged", "untracked"]


@dataclass(frozen=True, slots=True)
class LoopDecision:
    flagged: bool  # this call is the limit-th (or later) identical call in the window
    count: int  # estimated identical calls in the window, including this one (0 when untracked)
    outcome: Outcome


_UNTRACKED = LoopDecision(flagged=False, count=0, outcome="untracked")


class _Slot:
    """Two buckets of one window: the current one and the one before it."""

    __slots__ = ("start", "current", "previous")

    def __init__(self, start: float) -> None:
        self.start = start
        self.current = 0
        self.previous = 0


class LoopMeter:
    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys_per_agent: int = DEFAULT_MAX_KEYS_PER_AGENT,
        max_keys: int = DEFAULT_MAX_KEYS,
        salt: bytes | None = None,
    ) -> None:
        if max_keys_per_agent < 1 or max_keys < 1:
            raise ValueError("caps must be at least 1")
        self._clock = clock
        self._max_per_agent = max_keys_per_agent
        self._max_keys = max_keys
        self._salt = salt if salt is not None else os.urandom(16)
        # Least recently used first, at both levels.
        self._table: OrderedDict[UUID, OrderedDict[bytes, _Slot]] = OrderedDict()
        self._size = 0
        self.evictions = 0

    @property
    def size(self) -> int:
        """Keys held in all."""
        return self._size

    def agents(self) -> list[UUID]:
        return list(self._table)

    def keys_for(self, agent_id: UUID) -> list[bytes]:
        return list(self._table.get(agent_id, ()))

    def digest(self, tool_name: str, arguments: dict[str, Any]) -> bytes | None:
        """A salted 16-byte digest of the call, or None when the arguments cannot be serialized (so cannot be compared)."""
        try:
            text = json.dumps(arguments, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError, RecursionError):  # a set, an object, NaN, a non-string key, nesting too deep
            return None
        data = text.encode("ascii")  # json.dumps escapes everything else, so this cannot fail
        hasher = hashlib.blake2b(key=self._salt, digest_size=DIGEST_BYTES)
        hasher.update(len(tool_name.encode("utf-8")).to_bytes(4, "big"))  # the name and the arguments cannot run together
        hasher.update(tool_name.encode("utf-8"))
        if len(data) > MAX_HASHED_BYTES:
            hasher.update(data[:MAX_HASHED_BYTES])
            hasher.update(len(data).to_bytes(8, "big"))
        else:
            hasher.update(data)
        return hasher.digest()

    def check(
        self, agent_id: UUID, tool_name: str, arguments: dict[str, Any], *, limit: int, window_seconds: float, throttle: bool,
    ) -> LoopDecision:
        """
        Counts one call and says whether it is the `limit`-th identical call in the last `window_seconds` (calls 1 to limit-1 are
        not flagged). With `throttle` a flagged call is NOT counted, so the caller is refused only while the window still holds
        that many calls and recovers as it moves on; without it every call is counted. Raises ValueError for a limit or window
        that makes no sense (the gateway treats any exception as an error).
        """
        if limit < 1 or window_seconds <= 0:
            raise ValueError("limit must be at least 1 and the window positive")
        digest = self.digest(tool_name, arguments)
        if digest is None:
            return _UNTRACKED
        slot = self._slot(agent_id, digest)
        now = self._clock()
        elapsed = now - slot.start
        if elapsed >= window_seconds:
            periods = int(elapsed // window_seconds)
            slot.previous = slot.current if periods == 1 else 0
            slot.current = 0
            slot.start += periods * window_seconds
            elapsed = now - slot.start
        estimate = slot.previous * (1.0 - elapsed / window_seconds) + slot.current + 1
        count = int(estimate + 1e-9)
        flagged = count >= limit
        if not (flagged and throttle):
            slot.current += 1
        return LoopDecision(flagged=flagged, count=count, outcome="flagged" if flagged else "ok")

    def _slot(self, agent_id: UUID, digest: bytes) -> _Slot:
        keys = self._table.get(agent_id)
        if keys is not None:
            self._table.move_to_end(agent_id)
            slot = keys.get(digest)
            if slot is not None:
                keys.move_to_end(digest)
                return slot
        else:
            keys = OrderedDict()
        if len(keys) >= self._max_per_agent:
            keys.popitem(last=False)
            self._size -= 1
            self.evictions += 1
        while self._size >= self._max_keys and self._table:
            self._drop_least_recently_used(keep=agent_id)
        slot = _Slot(self._clock())
        keys[digest] = slot
        self._table[agent_id] = keys
        self._table.move_to_end(agent_id)
        self._size += 1
        return slot

    def _drop_least_recently_used(self, *, keep: UUID) -> None:
        """Drops the oldest key of the least recently used agent (never the agent being served unless it is the only one)."""
        victim = next((a for a in self._table if a != keep), keep)
        keys = self._table[victim]
        keys.popitem(last=False)
        self._size -= 1
        self.evictions += 1
        if not keys:
            del self._table[victim]
