"""Command line: python -m agentwall.src.bench [--format text|json|markdown|ui-json|gate] [--out FILE] [--check BASELINE]."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .corpus import DEFAULT_CORPUS_DIR, corpus_digest, load_corpus
from .metrics import evaluate
from .report import baseline_is_current, compare_with_baseline, render_gate, render_json, render_markdown, render_text, render_ui_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redhand bench", description="Measure detection and false-alarm rates on the labelled corpus.")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS_DIR, help="directory of <category>.jsonl files")
    parser.add_argument("--format", choices=("text", "json", "markdown", "ui-json", "gate"), default="text")
    parser.add_argument("--out", type=Path, help="write the report here instead of printing it")
    parser.add_argument("--check", type=Path, metavar="BASELINE", help="fail (exit 1) if any category got worse than this baseline")
    parser.add_argument("--update-baseline", type=Path, metavar="BASELINE", help="write the current result as the new baseline")
    args = parser.parse_args(argv)

    try:
        samples = load_corpus(args.corpus)
    except ValueError as exc:
        print(f"corpus is invalid: {exc}", file=sys.stderr)
        return 2
    digest = corpus_digest(args.corpus)
    ev = evaluate(samples)

    if args.update_baseline:
        args.update_baseline.write_text(render_json(ev, digest), encoding="utf-8")
        print(f"baseline written to {args.update_baseline}")
    renderers = {"text": render_text, "json": render_json, "markdown": render_markdown, "ui-json": render_ui_json, "gate": render_gate}
    output = renderers[args.format](ev, digest)
    if args.out:
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output, end="")

    if args.check:
        baseline = json.loads(args.check.read_text(encoding="utf-8"))
        problems = compare_with_baseline(ev, digest, baseline)
        if problems:
            print("REGRESSION:", *problems, sep="\n  ", file=sys.stderr)
            return 1
        if not baseline_is_current(ev, digest, baseline):
            print("note: results improved or changed; run with --update-baseline to record them", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
