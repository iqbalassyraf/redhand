"""Rates, confidence intervals and the coverage status rules. Pure functions: no I/O."""

from __future__ import annotations

from dataclasses import dataclass, field
import math

from .corpus import CATEGORY_OWASP, Sample
from .detectors import DETECTORS, Detector, flagged_by

MIN_SAMPLES_PER_SIDE = 20  # below this a category is reported as "insufficient data", never as covered

# Status thresholds, fixed in advance and printed with the report (changing them is a reviewed change).
COVERED_DETECTION, COVERED_FALSE_ALARM = 0.90, 0.01
PARTIAL_DETECTION, PARTIAL_FALSE_ALARM = 0.50, 0.05


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion; wide when the sample is small, which is the point."""
    if total == 0:
        return (0.0, 1.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


@dataclass(slots=True)
class CategoryResult:
    category: str
    owasp: str
    n_malicious: int = 0
    n_benign: int = 0
    families: int = 0
    detected: int = 0
    false_alarms: int = 0
    hard_benign: int = 0
    hard_false_alarms: int = 0
    by_lang: dict[str, tuple[int, int]] = field(default_factory=dict)  # lang -> (malicious, detected)
    missed: list[str] = field(default_factory=list)
    false_alarm_ids: list[str] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        return self.detected / self.n_malicious if self.n_malicious else 0.0

    @property
    def false_alarm_rate(self) -> float:
        return self.false_alarms / self.n_benign if self.n_benign else 0.0

    @property
    def detection_interval(self) -> tuple[float, float]:
        return wilson(self.detected, self.n_malicious)

    @property
    def false_alarm_interval(self) -> tuple[float, float]:
        return wilson(self.false_alarms, self.n_benign)

    @property
    def status(self) -> str:
        if self.n_malicious < MIN_SAMPLES_PER_SIDE or self.n_benign < MIN_SAMPLES_PER_SIDE:
            return "insufficient data"
        d, f = self.detection_rate, self.false_alarm_rate
        if d == 0:
            return "not covered"
        if d >= COVERED_DETECTION and f <= COVERED_FALSE_ALARM:
            return "covered"
        if d >= PARTIAL_DETECTION and f <= PARTIAL_FALSE_ALARM:
            return "partial"
        return "weak"


@dataclass(slots=True)
class Evaluation:
    categories: dict[str, CategoryResult]  # dev samples: used to write and tune rules, so they flatter them
    detectors: tuple[str, ...]
    holdout: dict[str, CategoryResult] = field(default_factory=dict)  # held-out samples: reporting only, never tuned on

    def headline(self, category: str) -> tuple[CategoryResult, str]:
        """The result to quote for a category: held-out when it has enough samples on both sides, else dev (labelled)."""
        held = self.holdout.get(category)
        if held is not None and held.n_malicious >= MIN_SAMPLES_PER_SIDE and held.n_benign >= MIN_SAMPLES_PER_SIDE:
            return held, "held-out"
        return self.categories[category], "dev only"

    @property
    def total_samples(self) -> int:
        return sum(c.n_malicious + c.n_benign for c in (*self.categories.values(), *self.holdout.values()))


def evaluate(samples: list[Sample], detectors: tuple[Detector, ...] = DETECTORS) -> Evaluation:
    dev, held = _evaluate_split([s for s in samples if s.split == "dev"], detectors), \
        _evaluate_split([s for s in samples if s.split == "holdout"], detectors)
    return Evaluation(dev, tuple(d.name for d in detectors), held)


def _evaluate_split(samples: list[Sample], detectors: tuple[Detector, ...]) -> dict[str, CategoryResult]:
    results: dict[str, CategoryResult] = {}
    families: dict[str, set[str]] = {}
    for sample in samples:
        res = results.setdefault(sample.category, CategoryResult(sample.category, CATEGORY_OWASP[sample.category]))
        hit = bool(flagged_by(sample, detectors))
        if sample.label == "malicious":
            res.n_malicious += 1
            families.setdefault(sample.category, set()).add(sample.family)
            total, found = res.by_lang.get(sample.lang, (0, 0))
            res.by_lang[sample.lang] = (total + 1, found + (1 if hit else 0))
            if hit:
                res.detected += 1
            else:
                res.missed.append(sample.id)
        else:
            res.n_benign += 1
            if sample.hard:
                res.hard_benign += 1
            if hit:
                res.false_alarms += 1
                res.false_alarm_ids.append(sample.id)
                if sample.hard:
                    res.hard_false_alarms += 1
    for category, fams in families.items():
        results[category].families = len(fams)
    return dict(sorted(results.items()))
