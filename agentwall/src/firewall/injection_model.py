"""
The Radar's second stage for indirect injection (Phase 4 M4.1c): a small linear model over character and word n-grams of
three-sentence windows, scored in pure Python from a plain JSON file (no pickle, no numpy, no new dependency).

Why it exists: the rules (radar.py) find about 4 in 10 subtle attacks on blind data. This model ranks text better (blind-round
cross-validation AUC about 0.93 against rules that cannot rank) but its calibration shifts between authors, so it is conservative:
only a score of 0.9 or more is actionable, 0.7 to 0.9 is recorded as low confidence, and it is NOT part of the default (hot path)
detector set. It costs about a millisecond per window, so it belongs on a background path, bounded by MAX_WINDOWS.

The scorer reproduces scikit-learn's TfidfVectorizer (sublinear tf, smoothed idf, l2 norm per vectorizer) and LogisticRegression
exactly; a test checks it against probabilities scikit-learn produced at training time (the manifest's parity vectors).
Like every Radar finding, a model finding carries no scanned text.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
import math
from pathlib import Path
import re
from typing import Any

from . import radar

MODEL_PATH = Path(__file__).resolve().parent / "models" / "injection_v1.json"
MAX_MODEL_BYTES = 12 * 1024 * 1024
MAX_WINDOWS = 48  # first and last 24 windows of a long result: bounded work, like the rest of the Radar
WINDOW = 3
RECORD_AT = 0.70  # recorded as low confidence (visible, never alerts)
ACTIONABLE_AT = 0.90  # medium confidence: alerts
HIGH_AT = 0.95

_WORD_TOKEN = re.compile(r"(?u)\b\w\w+\b")
_WHITESPACE = re.compile(r"\s\s+")


class ModelError(Exception):
    """The model file is missing, too large or malformed. The second stage then reports nothing; enforcement is unaffected."""


def segments(text: str) -> list[str]:
    """The sentence split the model was trained on (the Radar's own, applied to normalised text)."""
    return segments_of_clean(radar.prepare(text).clean) or [text.lower()]


def segments_of_clean(clean: str) -> list[str]:
    return radar._segments(clean)


def windows(segs: list[str], size: int = WINDOW) -> list[str]:
    return [" ".join(segs[i: i + size]) for i in range(len(segs))] or list(segs)


def _word_ngrams(text: str, low: int, high: int) -> list[str]:
    tokens = _WORD_TOKEN.findall(text.lower())
    out = list(tokens) if low == 1 else []
    for n in range(max(low, 2), high + 1):
        out.extend(" ".join(tokens[i: i + n]) for i in range(len(tokens) - n + 1))
    return out


def _char_wb_ngrams(text: str, low: int, high: int) -> list[str]:
    """scikit-learn's analyzer="char_wb": character n-grams inside word boundaries, each word padded with one space."""
    out: list[str] = []
    for word in _WHITESPACE.sub(" ", text.lower()).split():
        padded = f" {word} "
        length = len(padded)
        for n in range(low, high + 1):
            offset = 0
            out.append(padded[offset: offset + n])
            while offset + n < length:
                offset += 1
                out.append(padded[offset: offset + n])
            if offset == 0:  # the word is shorter than n
                break
    return out


@dataclass(frozen=True, slots=True)
class _Table:
    ngram: tuple[int, int]
    weights: dict[str, tuple[float, float]]  # term -> (idf, coefficient)


@dataclass(frozen=True, slots=True)
class InjectionModel:
    word: _Table
    char: _Table
    intercept: float
    window: int
    manifest: dict[str, Any]

    def _logit_part(self, terms: list[str], table: _Table) -> float:
        counts: dict[str, int] = {}
        for term in terms:
            if term in table.weights:
                counts[term] = counts.get(term, 0) + 1
        if not counts:
            return 0.0
        weighted = {t: (1.0 + math.log(c)) * table.weights[t][0] for t, c in counts.items()}  # sublinear tf times idf
        norm = math.sqrt(sum(w * w for w in weighted.values()))
        return sum(table.weights[t][1] * w / norm for t, w in weighted.items()) if norm else 0.0

    def piece_probability(self, piece: str) -> float:
        logit = (
            self.intercept
            + self._logit_part(_word_ngrams(piece, *self.word.ngram), self.word)
            + self._logit_part(_char_wb_ngrams(piece, *self.char.ngram), self.char)
        )
        if logit >= 0:
            return 1.0 / (1.0 + math.exp(-logit))
        e = math.exp(logit)
        return e / (1.0 + e)

    def score_segments(self, segs: list[str]) -> float:
        """The mean of the two highest window probabilities (a short document has one window)."""
        pieces = windows(segs, self.window)
        if len(pieces) > MAX_WINDOWS:
            half = MAX_WINDOWS // 2
            pieces = pieces[:half] + pieces[-half:]
        probabilities = sorted(self.piece_probability(p) for p in pieces)
        top = probabilities[-2:]
        return sum(top) / len(top) if top else 0.0

    def score(self, text: str) -> float:
        return self.score_segments(segments(text))


def _table(raw: dict[str, Any], coef: list[float], offset: int) -> _Table:
    vocab, idf = raw["vocab"], raw["idf"]
    if len(vocab) != len(idf):
        raise ModelError("vocabulary and idf lengths differ")
    return _Table((int(raw["ngram"][0]), int(raw["ngram"][1])), {t: (float(idf[i]), float(coef[offset + i])) for t, i in vocab.items()})


@lru_cache(maxsize=1)
def load(path: Path = MODEL_PATH) -> InjectionModel:
    try:
        if path.stat().st_size > MAX_MODEL_BYTES:
            raise ModelError("model file is larger than allowed")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("format") != 1 or raw.get("kind") != "indirect_injection_window_logreg":
            raise ModelError("unknown model format")
        coef = [float(c) for c in raw["coef"]]
        n_word = len(raw["word"]["vocab"])
        if len(coef) != n_word + len(raw["char"]["vocab"]) or raw["n_word_features"] != n_word:
            raise ModelError("coefficient count does not match the vocabularies")
        return InjectionModel(_table(raw["word"], coef, 0), _table(raw["char"], coef, n_word), float(raw["intercept"]), int(raw["window"]), dict(raw["manifest"]))
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        raise ModelError(f"{type(exc).__name__}") from None


def available() -> bool:
    try:
        load()
    except ModelError:
        return False
    return True


class ModelDetector:
    """A radar.Detector for the second stage. Not in the default (hot path) set: add it where there is time to spend."""

    name = "injection_model"

    def scan(self, prepared: radar.Prepared, ctx: radar.ScanContext) -> list[radar.Finding]:
        try:
            probability = load().score_segments(segments_of_clean(prepared.clean) or [prepared.clean])
        except ModelError:
            return []
        if probability < RECORD_AT:
            return []
        confidence: radar.Level = "high" if probability >= HIGH_AT else "medium" if probability >= ACTIONABLE_AT else "low"
        return [radar._finding("RAD-INJ-012", "text", confidence, prepared.evasion)]


SECOND_STAGE: tuple[radar.Detector, ...] = (ModelDetector(),)
RULES_AND_MODEL: tuple[radar.Detector, ...] = (*radar.DEFAULT_DETECTORS, *SECOND_STAGE)
