#!/usr/bin/env python3
"""Checks a blind-round file (JSONL) against the brief: fields, ids, labels, languages, sizes and counts. Standard library only; reads one file; prints numbers, never text.

Usage: python3 validate_blind_round.py blind4-injection_indirect.jsonl
"""

import json
import re
import sys

FIELDS = {"id", "category", "kind", "label", "lang", "family", "hard", "text"}
MIN_MALICIOUS, MIN_BENIGN, MIN_HARD, MIN_LONG_BENIGN, MIN_LONG_MALICIOUS, FIRST_ID, LONG_BYTES = 100, 150, 50, 50, 10, 1001, 2048
SECRET = re.compile(r"sk-[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,}")


def main(path: str) -> int:
    problems: list[str] = []
    rows = []
    for number, line in enumerate(open(path, encoding="utf-8").read().splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            problems.append(f"line {number}: not valid JSON")
            continue
        if not isinstance(row, dict) or set(row) != FIELDS:
            problems.append(f"line {number}: the fields must be exactly {sorted(FIELDS)}")
            continue
        rows.append((number, row))
    seen_text: set[str] = set()
    seen_id: set[str] = set()
    kept = []
    for number, row in rows:
        m = re.fullmatch(r"injection_indirect-(\d{4})", str(row["id"]))
        if not m or int(m.group(1)) < FIRST_ID:
            problems.append(f"line {number}: id must look like injection_indirect-1001 (numbers from {FIRST_ID})")
        if row["id"] in seen_id:
            problems.append(f"line {number}: duplicate id")
        seen_id.add(row["id"])
        if row["category"] != "injection_indirect" or row["kind"] != "tool_result":
            problems.append(f"line {number}: category must be injection_indirect and kind tool_result")
        if row["label"] not in ("malicious", "benign"):
            problems.append(f"line {number}: label must be malicious or benign")
        if row["lang"] not in ("en", "ms"):
            problems.append(f"line {number}: lang must be en or ms")
        if not isinstance(row["family"], str) or not 1 <= len(row["family"]) <= 40:
            problems.append(f"line {number}: family must be 1 to 40 characters")
        if not isinstance(row["hard"], bool) or (row["hard"] and row["label"] != "benign"):
            problems.append(f"line {number}: hard must be true or false, and true only for benign samples")
        if not isinstance(row["text"], str) or not 20 <= len(row["text"]) <= 20000:
            problems.append(f"line {number}: text must be 20 to 20,000 characters")
            continue
        if SECRET.search(row["text"]):
            problems.append(f"line {number}: the text looks like a real secret: use an obviously fake value")
        if row["text"] in seen_text:
            problems.append(f"line {number}: the same text appears twice")
            continue
        seen_text.add(row["text"])
        kept.append(row)
    mal = [r for r in kept if r["label"] == "malicious"]
    ben = [r for r in kept if r["label"] == "benign"]
    long_bytes = lambda r: len(r["text"].encode("utf-8")) >= LONG_BYTES  # noqa: E731
    counts = {
        "malicious": (len(mal), MIN_MALICIOUS), "benign": (len(ben), MIN_BENIGN), "hard benign": (sum(r["hard"] for r in ben), MIN_HARD),
        "benign of 2 KiB or more": (sum(map(long_bytes, ben)), MIN_LONG_BENIGN), "malicious of 2 KiB or more": (sum(map(long_bytes, mal)), MIN_LONG_MALICIOUS),
    }
    for name, (have, need) in counts.items():
        print(f"{name}: {have} (need at least {need})")
        if have < need:
            problems.append(f"too few {name}: {have}, need {need}")
    total = len(kept) or 1
    ms = sum(r["lang"] == "ms" for r in kept)
    indonesian = sum(r["lang"] == "ms" and "indonesian" in r["family"].lower() for r in kept)
    english = total - ms
    print(f"English {english * 100 // total}%, Bahasa Malaysia {(ms - indonesian) * 100 // total}%, Indonesian {indonesian * 100 // total}% (aim: about 55, 30, 15)")
    if not (45 <= english * 100 / total <= 65 and 20 <= (ms - indonesian) * 100 / total <= 38 and 8 <= indonesian * 100 / total <= 22):
        problems.append("the language mix is far from 55% English, 30% Bahasa Malaysia, 15% Indonesian (Indonesian is lang ms with 'indonesian' in family)")
    for problem in problems[:40]:
        print("PROBLEM:", problem)
    print("OK: the file matches the brief" if not problems else f"{len(problems)} problem(s) to fix before sending")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
