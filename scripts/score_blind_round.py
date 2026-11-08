#!/usr/bin/env python3
"""
Scores one blind round (a JSONL file of injection_indirect samples) against the Radar, REPORT ONLY: nothing here changes a rule or a model.
Prints counts and sample ids, never sample text. Usage: uv run python scripts/score_blind_round.py docs/testing/exports/blind3-injection_indirect.jsonl
A sample counts as detected when the detectors return at least one actionable (not low confidence) injection finding.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

from agentwall.src.firewall import radar
from agentwall.src.firewall.injection_model import RULES_AND_MODEL, SECOND_STAGE

CONFIGS = {"rules only": radar.DEFAULT_DETECTORS, "model only": SECOND_STAGE, "rules + model": RULES_AND_MODEL}
KINDS = frozenset({"injection"})


def detected(text: str, detectors: tuple[radar.Detector, ...]) -> bool:
    report = radar.scan_result(text, radar.ScanContext(), KINDS, detectors)
    return any(f.actionable for f in report.findings)


def pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "0/0"


def main(path: str) -> None:
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    seen: set[str] = set()
    unique = [r for r in rows if not (r["text"] in seen or seen.add(r["text"]))]  # type: ignore[func-returns-value]
    print(f"{len(rows)} samples, {len(unique)} after removing {len(rows) - len(unique)} exact duplicates\n")
    for name, detectors in CONFIGS.items():
        result = {r["id"]: detected(r["text"], detectors) for r in unique}
        mal = [r for r in unique if r["label"] == "malicious"]
        ben = [r for r in unique if r["label"] == "benign"]
        hard = [r for r in ben if r["hard"]]
        print(f"== {name}")
        print(f"   attacks found      {pct(sum(result[r['id']] for r in mal), len(mal))}")
        print(f"   false alarms       {pct(sum(result[r['id']] for r in ben), len(ben))}   of which hard-benign {pct(sum(result[r['id']] for r in hard), len(hard))}, ordinary benign {pct(sum(result[r['id']] for r in ben if not r['hard']), len(ben) - len(hard))}")
        for lang in ("en", "ms"):
            m = [r for r in mal if r["lang"] == lang]
            b = [r for r in ben if r["lang"] == lang]
            print(f"   lang {lang}: attacks {pct(sum(result[r['id']] for r in m), len(m))}, false alarms {pct(sum(result[r['id']] for r in b), len(b))}")
        for label, lo, hi in (("short (<300 chars)", 0, 300), ("medium (300-499)", 300, 500), ("long (500+)", 500, 10**9)):
            m = [r for r in mal if lo <= len(r["text"]) < hi]
            print(f"   {label}: attacks {pct(sum(result[r['id']] for r in m), len(m))}")
        missed = collections.Counter(r["family"] for r in mal if not result[r["id"]])
        print("   missed attack families:", dict(missed.most_common(8)))
        print("   missed ids:", [r["id"].split("-")[-1] for r in mal if not result[r["id"]]])
        print("   false alarm ids:", [r["id"].split("-")[-1] for r in ben if result[r["id"]]])
        print()


if __name__ == "__main__":
    main(sys.argv[1])
