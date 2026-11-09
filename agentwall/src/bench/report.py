"""Renders an Evaluation as text, JSON or the coverage-matrix markdown, and compares it with a stored baseline."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from ..firewall.radar_fingerprint import rules_fingerprint
from .gate import evaluate_gate, gate_json, render_gate_text
from .metrics import (
    COVERED_DETECTION, COVERED_FALSE_ALARM, MIN_SAMPLES_PER_SIDE, PARTIAL_DETECTION, PARTIAL_FALSE_ALARM,
    CategoryResult, Evaluation, wilson,
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
    ("LLM07", "System Prompt Leakage", "Partly: a system-prompt canary (Honeytokens page) alerts when planted text appears in a tool call or a tool answer. "
     "Not measured here, and it cannot see a prompt shown to a person in chat."),
    ("LLM08", "Vector and Embedding Weaknesses", "Not covered: RAG checks are deferred (they need customer integration)."),
    ("LLM09", "Misinformation", "Not covered: outside what a control layer can judge."),
    ("LLM10", "Unbounded Consumption", "Budget Guard caps daily tool calls (tested elsewhere); not measured by this benchmark."),
)


@dataclass(frozen=True, slots=True)
class BlindRow:
    """One category of a frozen blind round: found/total attacks, false alarms/total benign, hard-benign false alarms/total hard benign."""

    category: str
    detected: int
    malicious: int
    false_alarms: int
    benign: int
    hard_false_alarms: int
    hard_benign: int
    long_benign: int = 0  # harmless samples of 2 KiB or more (block gate G5); counted from the samples, 0 when there are none


@dataclass(frozen=True, slots=True)
class BlindRound:
    key: str
    title: str
    author: str
    record: str  # the frozen document with the full account
    note: str
    rows: tuple[BlindRow, ...]
    # Block gate (agentwall/src/bench/gate.py): did this round's samples stay out of rule development, and which rules was it scored on?
    independent: bool = False
    scored_on: str | None = None  # rules fingerprint (agentwall/src/firewall/radar_fingerprint.py); None = those rules no longer exist


# The fingerprint of agentwall/src/firewall/radar.py that rounds 2 and 3 count for. Round 2 was scored on the commit before M4.1c, which differs
# from today's file by exactly one table row (RAD-INJ-012, used only by the helper model, so no rule that rounds 2 or 3 exercised changed);
# round 3 was scored on today's file. Verified with `git diff 52fdfeb HEAD -- agentwall/src/firewall/radar.py` on 2026-11-09. Any later edit of
# the rules file changes the fingerprint and the gate then says "needs a new round".
ROUND_2_AND_3_RULES = "a7818a78351aa02e"

# Frozen records. They are NOT recomputed (the samples became development data, or the rules changed afterwards); every number is copied
# from the document named in `record`, and a test checks that the intervals printed here follow from the counts.
BLIND_ROUNDS: tuple[BlindRound, ...] = (
    BlindRound(
        "round1", "Independent blind round 1 (frozen: the rules BEFORE they were improved)", "Antigravity (Gemini)", "docs/security/blind-round-1.md",
        "1,000 samples written by a different author from a brief with no rule text, measured once on the M4.1 rules. Those samples are now "
        "development data, so these numbers can only be refreshed by a new blind round.",
        (BlindRow("injection_indirect", 24, 100, 5, 150, 5, 35), BlindRow("output_xss", 98, 100, 13, 150, 13, 35),
         BlindRow("output_ssrf", 76, 100, 4, 150, 4, 35), BlindRow("output_path", 66, 100, 7, 150, 7, 35)),
    ),
    BlindRound(
        "round2", "Independent blind round 2 (frozen: the rewritten rules on harder, unseen samples)", "Antigravity (Gemini)", "docs/security/blind-round-2.md",
        "800 new samples by the same independent author, asked to be harder and more varied; one run on the rewritten rules. This is the best "
        "available estimate for output checks on text the rules have not seen. It is not comparable one to one with round 1.",
        (BlindRow("injection_indirect", 33, 80, 10, 120, 10, 45), BlindRow("output_xss", 74, 80, 0, 120, 0, 45),
         BlindRow("output_ssrf", 50, 80, 3, 120, 3, 45), BlindRow("output_path", 51, 80, 6, 120, 6, 45)),
        independent=True, scored_on=ROUND_2_AND_3_RULES,
    ),
    BlindRound(
        "round3", "Independent blind round 3 (frozen: hidden instructions only, a different author)", "Grok 4 (xAI)", "docs/security/blind-round-3.md",
        "250 samples (240 after removing exact duplicates) by an author that is not Gemini, scored once on the rules as the gateway runs them by "
        "default (the helper model is off and adds 2 attacks, 36 of 94). One author, labels not independently reviewed, few long harmless texts, "
        "and no Indonesian attacks. This is the best available estimate for hidden-instruction detection.",
        (BlindRow("injection_indirect", 34, 94, 10, 146, 5, 48),),
        independent=True, scored_on=ROUND_2_AND_3_RULES,
    ),
)

# Round 3 by language (rules only, after removing duplicates). Indonesian texts were all harmless, so Indonesian attacks were not measured.
BLIND3_LANGUAGES: dict[str, tuple[int, int, int, int]] = {  # code -> (attacks found, attacks, false alarms, harmless)
    "en": (30, 69, 5, 61), "ms": (4, 25, 3, 53), "id": (0, 0, 2, 32),
}

# What each language honestly has. `native_reviewed` is False everywhere: no native speaker has reviewed the rules or the samples
# (the Malay review file is waiting: docs/review/malay-samples-for-review.md).
LANGUAGES: tuple[dict[str, Any], ...] = (
    {"code": "en", "name": "English", "native_reviewed": False,
     "note": "Rules and samples were written by the team and by outside authors. Nobody has formally reviewed them."},
    {"code": "ms", "name": "Bahasa Malaysia", "native_reviewed": False,
     "note": "Has its own rules and samples, written without a native speaker. The review is waiting. Hidden-instruction detection is weak."},
    {"code": "id", "name": "Bahasa Indonesia", "native_reviewed": False,
     "note": "No Indonesian-specific rules. The only independent samples (round 3) were all harmless, so attack detection is not measured at all."},
    {"code": "zh", "name": "Chinese (Simplified)", "native_reviewed": False,
     "note": "Not covered: no rules and no samples. Do not assume anything here is detected."},
)

KNOWN_GAPS: tuple[str, ...] = (
    "Hidden instructions are found about 4 times in 10 on text the rules have not seen, with about 7 to 8 false alarms per 100 harmless documents.",
    "On real long documents the checks flag more than on our short samples: 10 of 10 real web pages raised a script flag, and on 186 strangers' READMEs the hidden-instruction check "
    "flagged 12% and the risky-output check 6% (a recorded measurement, not blind evidence: docs/security/real-document-replay.md).",
    "A rephrased or politely worded attack, and an attack buried in the middle of a long document, are often missed.",
    "Malay hidden-instruction detection found 4 of 25 attacks in the independent round; Indonesian attacks were not measured; Chinese is not covered.",
    "Documentation, runbooks and security write-ups that quote attacks cause false alarms.",
    "The helper model for hidden instructions is off: on unseen text it added almost nothing at its current settings.",
    "Secret leaks and MCP manifest risks have small sample sets (20 each) and are weak or partial.",
    "The Radar only sees what flows through the RedHand gateway. It never blocks: block mode does not exist until a measured gate is passed.",
)


def _blind_text(detected: int, total: int) -> str:
    low, high = wilson(detected, total)
    return f"{detected}/{total} = {_pct(detected / total)} ({_pct(low)} to {_pct(high)})"


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


def _result_json(c: CategoryResult, quotable: bool) -> dict[str, Any]:
    return {
        "category": c.category, "owasp": c.owasp, "malicious": c.n_malicious, "benign": c.n_benign, "families": c.families,
        "detected": c.detected, "false_alarms": c.false_alarms, "hard_benign": c.hard_benign, "hard_false_alarms": c.hard_false_alarms,
        "detection": _quotable(c.detected, c.n_malicious, c.detection_rate, c.detection_interval) if quotable
        else f"{c.detected}/{c.n_malicious} = {_pct(c.detection_rate)} ({_interval(c.detection_interval)})",
        "false_alarm_rate": _quotable(c.false_alarms, c.n_benign, c.false_alarm_rate, c.false_alarm_interval) if quotable
        else f"{c.false_alarms}/{c.n_benign} = {_pct(c.false_alarm_rate)} ({_interval(c.false_alarm_interval)})",
        "status": c.status,
        "by_lang": {lang: {"malicious": n, "detected": d} for lang, (n, d) in sorted(c.by_lang.items())},
    }


def to_ui_json(ev: Evaluation, digest: str) -> dict[str, Any]:
    """Everything the dashboard's Coverage page shows. Generated from the same evaluation as the Markdown matrix, so the two cannot differ."""
    return {
        "generated_by": "python -m agentwall.src.bench --format ui-json (do not edit by hand; a test fails if this file is out of date)",
        "corpus": digest,
        "total_samples": ev.total_samples,
        "detectors": list(ev.detectors),
        "status_rules": {
            "covered": f"detection at least {_pct(COVERED_DETECTION)} and false alarms at most {_pct(COVERED_FALSE_ALARM)}",
            "partial": f"detection at least {_pct(PARTIAL_DETECTION)} and false alarms at most {_pct(PARTIAL_FALSE_ALARM)}",
            "weak": "detects something but misses the partial bar",
            "not covered": "detects nothing",
            "insufficient data": f"fewer than {MIN_SAMPLES_PER_SIDE} samples on one side",
        },
        "holdout": [_result_json(c, True) for c in ev.holdout.values()],
        "dev": [_result_json(c, False) for c in ev.categories.values()],
        "blind_rounds": [
            {
                "key": r.key, "title": r.title, "author": r.author, "record": r.record, "note": r.note,
                "rows": [
                    {
                        "category": row.category, "detection": _blind_text(row.detected, row.malicious),
                        "false_alarms": _blind_text(row.false_alarms, row.benign), "hard_false_alarms": f"{row.hard_false_alarms}/{row.hard_benign}",
                        "detected": row.detected, "malicious": row.malicious,
                    }
                    for row in r.rows
                ],
            }
            for r in BLIND_ROUNDS
        ],
        "languages": [
            {
                **lang,
                "blind3": (
                    {"attacks_found": f, "attacks": a, "harmless_flagged": fa, "harmless": b}
                    if (f, a, fa, b) != (0, 0, 0, 0) else None
                ),
            }
            for lang in LANGUAGES
            for (f, a, fa, b) in [BLIND3_LANGUAGES.get(lang["code"], (0, 0, 0, 0))]
        ],
        "known_gaps": list(KNOWN_GAPS),
        "block_gate": gate_json(BLIND_ROUNDS, rules_fingerprint()),
        "owasp": [
            {
                "item": item, "name": name, "note": note,
                "status": [f"{c.category}: {ev.headline(c.category)[0].status}" for c in ev.categories.values() if c.owasp == item],
            }
            for item, name, note in OWASP_ITEMS
        ],
    }


def render_gate(ev: Evaluation, digest: str) -> str:
    """The block gate alone, as text. It reads only the frozen blind rounds and the rules fingerprint, so `ev` and `digest` are unused."""
    return render_gate_text(BLIND_ROUNDS, rules_fingerprint())


def _gate_markdown_lines() -> list[str]:
    fingerprint = rules_fingerprint()
    rules = gate_json(BLIND_ROUNDS, fingerprint)["rules"]
    lines = [
        "", "## Ready to block? (the block gate)", "",
        "Block mode does not exist: SQL, core and the gateway all refuse it. This table says whether the measured evidence would be enough to ever "
        "offer it. It reads only the frozen blind rounds above, never our own held-out samples, and a change to the rules file makes old rounds stale "
        f"(rules fingerprint `{fingerprint}`). Rules: " + " ".join(f"**{r['id']}** {r['name']}: {r['description']}" for r in rules),
        "",
        "| Check | Evidence | G1 | G2 | G3 | G4 | G5 | Eligible |", "|---|---|---|---|---|---|---|---|",
    ]
    gates = evaluate_gate(BLIND_ROUNDS, fingerprint)
    for g in gates:
        cells = " | ".join("pass" if r.passed else "**fail**" for r in g.results)
        lines.append(f"| {g.label} | {g.evidence_round or 'none'} | {cells} | {'**yes**' if g.eligible else 'no'} |")
    lines.append("")
    for g in gates:
        lines.append(f"- **{g.label}:** " + (" ".join(g.missing) if g.missing else "all rules pass."))
    return lines


def render_ui_json(ev: Evaluation, digest: str) -> str:
    return json.dumps(to_ui_json(ev, digest), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


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
    for rnd in BLIND_ROUNDS:
        lines += [
            "", f"## {rnd.title}", "", f"Author: {rnd.author}. {rnd.note} The full record is `{rnd.record}`.", "",
            "| Category | Detected (95% interval) | False alarms | False alarms on hard benign |", "|---|---|---|---|",
            *(
                f"| `{r.category}` | {_blind_text(r.detected, r.malicious)} | {_blind_text(r.false_alarms, r.benign)} | {r.hard_false_alarms}/{r.hard_benign} |"
                for r in rnd.rows
            ),
            "",
        ]
    lines += ["", "### Detection by language (dev malicious samples)", "", "| Category | English | Bahasa Malaysia |", "|---|---|---|"]
    for c in ev.categories.values():
        en, ms = c.by_lang.get("en", (0, 0)), c.by_lang.get("ms", (0, 0))
        lines.append(f"| `{c.category}` | {en[1]}/{en[0]} | {ms[1]}/{ms[0]} |")
    lines += ["", "## Language coverage", "", "| Language | Native-reviewed | Hidden-instruction attacks found (blind round 3) | Harmless texts flagged | What this means |", "|---|---|---|---|---|"]
    for lang in LANGUAGES:
        found, total, fa, benign = BLIND3_LANGUAGES.get(lang["code"], (0, 0, 0, 0))
        attacks = f"{found}/{total}" if total else "not measured"
        flagged = f"{fa}/{benign}" if benign else "not measured"
        lines.append(f"| {lang['name']} | {'yes' if lang['native_reviewed'] else 'no'} | {attacks} | {flagged} | {lang['note']} |")
    lines += _gate_markdown_lines()
    lines += ["", "## Known gaps (read these first)", "", *(f"- {gap}" for gap in KNOWN_GAPS)]
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
