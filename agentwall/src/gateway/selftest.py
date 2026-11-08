"""
Radar self-test (Phase 4 M4.5b, docs/plans/phase4-m4-5-selftest-coverage.md): runs the Radar exactly as THIS gateway process runs it over a fixed
bundled set of held-out samples and returns counts. It proves that the deployed Radar code behaves as measured on our samples. It does not
prove that any customer's agent traffic goes through the gateway, and it says nothing about attacks the samples do not contain.

Safety: no input at all (the sample set is fixed), no sample text and no sample ids leave this module (held-out misses are deliberately never
listed, so nobody can tune rules against them), the work is bounded and runs off the event loop, and an error produces an error, never numbers.
"""

from __future__ import annotations

import asyncio
from functools import lru_cache
import time
from typing import Any

from ..bench.corpus import Sample, corpus_digest, load_corpus
from ..bench.detectors import DETECTORS, Detector
from ..bench.metrics import evaluate, wilson

RADAR_CATEGORIES = frozenset({"injection_indirect", "output_xss", "output_ssrf", "output_path"})
LIMITS = (
    "This runs the Radar code in the gateway over our own held-out samples. It shows the deployed Radar behaves as measured; it does not show "
    "that your agents' traffic goes through the gateway, and it cannot show what the samples do not contain."
)


class SelfTestError(Exception):
    """The self-test could not produce a trustworthy result."""


@lru_cache(maxsize=1)
def _samples() -> tuple[tuple[Sample, ...], str]:
    samples = tuple(s for s in load_corpus() if s.split == "holdout" and s.category in RADAR_CATEGORIES)
    if not samples:
        raise SelfTestError("The bundled sample set is empty.")
    return samples, corpus_digest()


def detectors_for(model_enabled: bool) -> tuple[Detector, ...]:
    """The Radar detectors this gateway runs: the rules, plus the helper model only when it is switched on for this process."""
    wanted = {"radar", "radar_model"} if model_enabled else {"radar"}
    return tuple(d for d in DETECTORS if d.name in wanted)


def run_self_test(model_enabled: bool, clock: Any = time.perf_counter) -> dict[str, Any]:
    """Counts only. Raises SelfTestError on any failure, so a broken scanner can never be shown as a result."""
    started = clock()
    try:
        samples, digest = _samples()
        held = evaluate(list(samples), detectors_for(model_enabled)).holdout
    except SelfTestError:
        raise
    except Exception as exc:  # noqa: BLE001  turn any failure into one error; the caller reports it without numbers
        raise SelfTestError(type(exc).__name__) from None
    categories: list[dict[str, Any]] = []
    for name in sorted(RADAR_CATEGORIES):
        c = held.get(name)
        if c is None or c.n_malicious == 0 or c.n_benign == 0:
            raise SelfTestError(f"No samples for {name}.")
        det_low, det_high = wilson(c.detected, c.n_malicious)
        fa_low, fa_high = wilson(c.false_alarms, c.n_benign)
        categories.append({
            "category": name, "malicious": c.n_malicious, "benign": c.n_benign,
            "detected": c.detected, "false_alarms": c.false_alarms,
            "detection_low": det_low, "detection_high": det_high,
            "false_alarm_low": fa_low, "false_alarm_high": fa_high,
            "hard_benign": c.hard_benign, "hard_false_alarms": c.hard_false_alarms,
        })
    return {
        "corpus": digest,
        "model_enabled": model_enabled,
        "samples": sum(c["malicious"] + c["benign"] for c in categories),
        "duration_ms": round((clock() - started) * 1000, 1),
        "categories": categories,
        "limits": LIMITS,
    }


class SelfTestRunner:
    """One run at a time for the whole process; a second request while one runs is refused instead of queued."""

    def __init__(self, model_enabled: bool) -> None:
        self._model_enabled = model_enabled
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    async def run(self) -> dict[str, Any]:
        if self._running:
            raise BusyError()
        self._running = True
        try:
            return await asyncio.to_thread(run_self_test, self._model_enabled)
        finally:
            self._running = False


class BusyError(Exception):
    """A self-test is already running in this process."""
