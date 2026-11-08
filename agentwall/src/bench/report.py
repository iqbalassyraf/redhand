"""Renders an Evaluation as text, JSON or the coverage-matrix markdown, and compares it with a stored baseline."""

from __future__ import annotations

import json
from typing import Any

from .metrics import (
    COVERED_DETECTION, COVERED_FALSE_ALARM, MIN_SAMPLES_PER_SIDE, PARTIAL_DETECTION, PARTIAL_FALSE_ALARM,
    CategoryResult, Evaluation,
)

# The OWASP LLM Top 10 (2025) items as the project understands them. Verify against the current publication before
# quoting externally. Items with no benchmark category say plainly why.
OWASP_ITEMS: tuple[tuple[str, str, str], ...] = (
    ("LLM01", "Prompt Injection", ""),
    ("LLM02", "Sensitive Information Disclosure", ""),
    ("LLM03", "Supply Chain", "Only the MCP manifest audit touches this (see manifest_risk). Package and model provenance are not checked."),
    ("LLM04", "Data and Model Poisoning", "Not covered: RedHand does not see training or fine-tuning data."),
    ("LLM05", "Improper Output Handling", ""),
    ("LLM06", "Excessive Agency", ""),
    ("LLM07", "System Prompt Leakage", "Not measured here. System-prompt canaries are planned (Phase 4 M5)."),
    ("LLM08", "Vector and Embedding Weaknesses", "Not covered: RAG checks are deferred (they need customer integration)."),
    ("LLM09", "Misinformation", "Not covered: outside what a control layer can judge."),
    ("LLM10", "Unbounded Consumption", "Budget Guard caps daily tool calls (tested elsewhere); not measured by this benchmark."),
)


# Frozen record of blind round 2 (docs/security/blind-round-2.md): the rewritten rules on harder, unseen samples (not comparable one to one with round 1).
BLIND_ROUND_2: tuple[tuple[str, str, str, str], ...] = (
    ("injection_indirect", "33/80 = 41% (31% to 52%)", "10/120 = 8% (5% to 15%)", "10/45"),
    ("output_xss", "74/80 = 92% (85% to 97%)", "0/120 = 0% (0% to 3%)", "0/45"),
    ("output_ssrf", "50/80 = 62% (52% to 72%)", "3/120 = 2% (1% to 7%)", "3/45"),
    ("output_path", "51/80 = 64% (53% to 73%)", "6/120 = 5% (2% to 10%)", "6/45"),
)

# Frozen record of blind round 1 (docs/security/blind-round-1.md). Not recomputed: the samples became development data afterwards.
BLIND_ROUND_1: tuple[tuple[str, str, str, str], ...] = (
    ("injection_indirect", "24/100 = 24% (17% to 33%)", "5/150 = 3% (1% to 8%)", "5/35"),
    ("output_xss", "98/100 = 98% (93% to 99%)", "13/150 = 9% (5% to 14%)", "13/35"),
    ("output_ssrf", "76/100 = 76% (67% to 83%)", "4/150 = 3% (1% to 7%)", "4/35"),
    ("output_path", "66/100 = 66% (56% to 75%)", "7/150 = 5% (2% to 9%)", "7/35"),
)


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def _interval(pair: tuple[float, float]) -> str:
    return f"{_pct(pair[0])}-{_pct(pair[1])}"


def _quotable(count: int, total: int, rate: float, interval: tuple[float, float]) -> str:
    """A rate that is meant to be quoted. A flat 100% or 0% from a few samples is a bound, not a measurement, so it is shown as one."""
    if count == total:
        return f"{count}/{total} (at least {_pct(interval[0])} with 95% confidence)"
    if count == 0:
        return f"{count}/{total} (at most {_pct(interval[1])} with 95% confidence)"
    return f"{count}/{total} = {_pct(rate)} ({_interval(interval)})"


def _text_rows(results: dict[str, CategoryResult]) -> list[str]:
    rows = ["category              mal  ben  fams  detected  95% CI      false alarms  95% CI     status"]
    for r in results.values():
        rows.append(
            f"{r.category:<20} {r.n_malicious:>4} {r.n_benign:>4} {r.families:>5}  "
            f"{r.detected:>3}/{r.n_malicious:<3} {_pct(r.detection_rate):>4}  {_interval(r.detection_interval):<10}  "
            f"{r.false_alarms:>3}/{r.n_benign:<3} {_pct(r.false_alarm_rate):>4}  {_interval(r.false_alarm_interval):<9}  {r.status}"
        )
    return rows


def render_text(ev: Evaluation, digest: str) -> str:
    rows = ["DEV samples (used to write and tune rules, so they flatter them):"] + _text_rows(ev.categories)
    if ev.holdout:
        rows += ["", "HELD-OUT samples (never tuned on; quote these when they exist):"] + _text_rows(ev.holdout)
    head = [
        f"redhand bench: corpus {digest}, {ev.total_samples} samples, detectors: {', '.join(ev.detectors)}",
        f"status rules: covered = detection >= {_pct(COVERED_DETECTION)} and false alarms <= {_pct(COVERED_FALSE_ALARM)}; "
        f"partial = >= {_pct(PARTIAL_DETECTION)} and <= {_pct(PARTIAL_FALSE_ALARM)}; at least {MIN_SAMPLES_PER_SIDE} samples per side or "
        "'insufficient data'.",
        "",
    ]
    return "\n".join(head + rows) + "\n"


def _category_json(results: dict[str, CategoryResult]) -> dict[str, Any]:
    return {
        c.category: {
            "owasp": c.owasp, "malicious": c.n_malicious, "benign": c.n_benign, "families": c.families,
            "detected": c.detected, "false_alarms": c.false_alarms, "hard_benign": c.hard_benign,
            "hard_false_alarms": c.hard_false_alarms, "status": c.status,
            "by_lang": {lang: {"malicious": n, "detected": d} for lang, (n, d) in sorted(c.by_lang.items())},
        }
        for c in results.values()
    }


def to_json(ev: Evaluation, digest: str) -> dict[str, Any]:
    return {
        "corpus": digest,
        "detectors": list(ev.detectors),
        "categories": _category_json(ev.categories),
        "holdout": _category_json(ev.holdout),
    }


def render_json(ev: Evaluation, digest: str) -> str:
    return json.dumps(to_json(ev, digest), indent=2, sort_keys=True) + "\n"


def render_markdown(ev: Evaluation, digest: str) -> str:
    lines = [
        "# Detection coverage (generated)",
        "",
        "<!-- Generated by `python -m agentwall.src.bench --format markdown`; do not edit by hand. A test fails if this "
        "file differs from a fresh run. -->",
        "",
        f"Corpus `{digest}`: {ev.total_samples} labelled samples written by the RedHand team, in English and Bahasa "
        "Malaysia. Detectors measured: " + ", ".join(f"`{d}`" for d in ev.detectors) + ".",
        "",
        "**How to read this.** The corpus is small and written by us, so these numbers flatter the detectors: real "
        "attackers rephrase, and variants of one idea are correlated (see the families column). The 95% intervals show "
        "how uncertain a rate is at this size. Nothing here means RedHand blocks 100% of anything, and RedHand only "
        "checks what flows through its gateway.",
        "",
        f"Status rules (fixed in advance): **covered** = detection >= {_pct(COVERED_DETECTION)} and false alarms <= "
        f"{_pct(COVERED_FALSE_ALARM)}; **partial** = >= {_pct(PARTIAL_DETECTION)} and <= {_pct(PARTIAL_FALSE_ALARM)}; "
        f"**weak** = detects something but misses the partial bar; **not covered** = detects nothing. A category with "
        f"fewer than {MIN_SAMPLES_PER_SIDE} samples on either side is **insufficient data**.",
        "",
        "## Dev results (the rules were written and tuned against these, and the `radar_model` detector was trained on them, so they flatter them)",
        "",
        "| Category | OWASP | Malicious | Benign | Families | Detection (95% CI) | False alarms (95% CI) | Hard benign false alarms | Status |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for c in ev.categories.values():
        lines.append(
            f"| `{c.category}` | {c.owasp} | {c.n_malicious} | {c.n_benign} | {c.families} | "
            f"{c.detected}/{c.n_malicious} = {_pct(c.detection_rate)} ({_interval(c.detection_interval)}) | "
            f"{c.false_alarms}/{c.n_benign} = {_pct(c.false_alarm_rate)} ({_interval(c.false_alarm_interval)}) | "
            f"{c.hard_false_alarms}/{c.hard_benign} | **{c.status}** |"
        )
    if ev.holdout:
        lines += [
            "", "## Held-out results (never tuned on: quote these)", "",
            "Held-out samples are not used to write or tune rules (a change made after seeing them is disclosed where it happens). "
            "A held-out set written by the same author as the rules is less independent than one written by someone else, and 20 "
            "samples can only prove so much: read the confidence interval, not the point estimate. A category with a held-out set "
            "is rated on it; the dev table above is what the rules were written against.", "",
            "| Category | OWASP | Malicious | Benign | Detection (95% CI) | False alarms (95% CI) | Hard benign false alarms | Status |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for c in ev.holdout.values():
            lines.append(
                f"| `{c.category}` | {c.owasp} | {c.n_malicious} | {c.n_benign} | "
                f"{_quotable(c.detected, c.n_malicious, c.detection_rate, c.detection_interval)} | "
                f"{_quotable(c.false_alarms, c.n_benign, c.false_alarm_rate, c.false_alarm_interval)} | "
                f"{c.hard_false_alarms}/{c.hard_benign} | **{c.status}** |"
            )
    if ev.holdout:
        lines += [
            "",
            "Status is assigned from point estimates, by rules fixed in M1. With 20 benign samples the false alarm rate is only known "
            "to be below about 16%, so read **covered** here as \"no misses found yet\", not as a guarantee. The corpus grows with "
            "independently written samples (plan `docs/plans/phase4-m4-plan.md`, section 11.3) and the status rule moves to the upper "
            "confidence bound at M4.6.",
        ]
    lines += [
        "", "## Independent blind round 1 (frozen: the rules BEFORE they were improved)", "",
        "1,000 samples written by a different author (Antigravity) from a brief with no rule text, measured once on the M4.1 rules; the "
        "full record is `docs/security/blind-round-1.md`. Those samples are now development data, so these numbers can only be "
        "refreshed by a new blind round.",
        "", "| Category | Detected (95% interval) | False alarms | False alarms on hard benign |", "|---|---|---|---|",
        *(f"| `{c}` | {d} | {fa} | {hb} |" for c, d, fa, hb in BLIND_ROUND_1),
        "",
        "## Independent blind round 2 (frozen: the rewritten rules on harder, unseen samples)", "",
        "800 new samples by the same independent author, asked to be harder and more varied; one run on the rewritten rules (`docs/security/blind-round-2.md`). "
        "This is the best available estimate of performance on text the rules have not seen. It is not comparable one to one with round 1.",
        "", "| Category | Detected (95% interval) | False alarms | False alarms on hard benign |", "|---|---|---|---|",
        *(f"| `{c}` | {d} | {fa} | {hb} |" for c, d, fa, hb in BLIND_ROUND_2),
        "",
    ]
    lines += ["", "### Detection by language (dev malicious samples)", "", "| Category | English | Bahasa Malaysia |", "|---|---|---|"]
    for c in ev.categories.values():
        en, ms = c.by_lang.get("en", (0, 0)), c.by_lang.get("ms", (0, 0))
        lines.append(f"| `{c.category}` | {en[1]}/{en[0]} | {ms[1]}/{ms[0]} |")
    lines += ["", "## OWASP LLM Top 10 (2025 numbering as understood by the project; verify before quoting)", "",
              "| Item | Name | Benchmark categories and status | Notes |", "|---|---|---|---|"]
    for item, name, note in OWASP_ITEMS:
        cats = [c for c in ev.categories.values() if c.owasp == item]
        status = "; ".join(
            f"`{c.category}`: {ev.headline(c.category)[0].status} ({ev.headline(c.category)[1]})" for c in cats
        ) if cats else "not measured"
        lines.append(f"| {item} | {name} | {status} | {note} |")
    lines += ["", "## Missed dev samples and false alarms (for the rule authors; held-out misses are deliberately not listed)", ""]
    for c in ev.categories.values():
        if c.missed or c.false_alarm_ids:
            lines.append(f"- `{c.category}`: missed {', '.join(c.missed) or 'none'}; false alarms {', '.join(c.false_alarm_ids) or 'none'}")
    return "\n".join(lines) + "\n"


def compare_with_baseline(ev: Evaluation, digest: str, baseline: dict[str, Any]) -> list[str]:
    """Problems that should fail CI: the corpus changed without a new baseline, or a category got worse."""
    problems: list[str] = []
    if baseline.get("corpus") != digest:
        problems.append(f"corpus changed ({baseline.get('corpus')} -> {digest}): regenerate the baseline on purpose")
        return problems
    for section, current in (("categories", ev.categories), ("holdout", ev.holdout)):
        base = baseline.get(section, {})
        label = "" if section == "categories" else " (held-out)"
        for name, cat in current.items():
            before = base.get(name)
            if before is None:
                problems.append(f"{name}{label}: not in the baseline")
                continue
            if cat.detected < before["detected"]:
                problems.append(f"{name}{label}: detection fell from {before['detected']} to {cat.detected} of {cat.n_malicious}")
            if cat.false_alarms > before["false_alarms"]:
                problems.append(f"{name}{label}: false alarms rose from {before['false_alarms']} to {cat.false_alarms} of {cat.n_benign}")
        for name in base:
            if name not in current:
                problems.append(f"{name}{label}: in the baseline but missing from the corpus")
    return problems


def baseline_is_current(ev: Evaluation, digest: str, baseline: dict[str, Any]) -> bool:
    """True when the stored baseline equals a fresh run exactly (so improvements are recorded, not silently kept)."""
    return to_json(ev, digest) == baseline


def describe_changes(cat: CategoryResult) -> str:
    return f"{cat.category}: {cat.detected}/{cat.n_malicious} detected, {cat.false_alarms}/{cat.n_benign} false alarms"
