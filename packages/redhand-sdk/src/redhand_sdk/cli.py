"""
RedHand CLI - Command Line Interface for Agentic Security Posture Management
File: packages/redhand-sdk/src/redhand_sdk/cli.py

Usage:
  redhand scan [path] [--sarif <path>] [--strict] [--baseline <file>] [--emit-baseline <file>]
  redhand fuzz
  redhand version
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from redhand_sdk.scanner.ast_checker import ScanFinding, scan_directory, scan_python_file
from redhand_sdk.scanner.baseline import BaselineError, apply_baseline, entries_for, load_baseline, normalize_path
from redhand_sdk.scanner.fuzzer import run_adversarial_fuzz_suite
from redhand_sdk.scanner.sarif import export_sarif_v2
from redhand_sdk.scanner.secrets import scan_secrets, summary_lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="redhand",
        description="RedHand: Zero-Trust Agentic Security Posture Management (ASPM) CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. 'scan' subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan Python agent code for security anti-patterns, and prompt and config files for pasted secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Two checks. (1) Python agent tools: missing @guard, broad IAM wildcards, unguarded destructive tools (RH-SEC-001 to 003).\n"
            "(2) Secrets in prompt and config files (RH-SEC-004): prints file, line and kind, NEVER the value.\n\n"
            "The secrets check reads .env, .env.*, .yaml, .yml, .json, .toml, .md, .txt and .py files, and finds only these key\n"
            "formats: Anthropic, OpenAI-style, AWS access key id, Google Cloud access token, and private key headers. It does not\n"
            "find passwords, database URLs or custom tokens. It skips files over 1 MiB, binary files, symlinks, and the folders\n"
            ".git, node_modules, .venv and __pycache__; it stops at 5,000 files and reports at most 50 findings per file.\n"
            "It makes no network call. A clean result is not a guarantee, and a found secret must be rotated (git history keeps it)."
        ),
    )
    scan_parser.add_argument("path", nargs="?", default=".", help="Path to Python file or repository root")
    scan_parser.add_argument("--sarif", help="Export findings to SARIF 2.1.0 JSON file")
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with non-zero code if any security findings are detected (CI gate)",
    )

    scan_parser.add_argument(
        "--baseline",
        help="A reviewed list of accepted findings (file, rule, SHA-256 of the line, reason). A finding not in it fails; so does an entry that no longer "
        "matches. A missing or invalid baseline exits 2. Run from the repository root with path '.'",
    )
    scan_parser.add_argument(
        "--emit-baseline",
        help="Write baseline entries for the current findings to a NEW file (never overwrites). Each reason is a TODO that must be replaced before use",
    )

    # 2. 'fuzz' subcommand
    subparsers.add_parser("fuzz", help="Benchmark <50ms Semantic Firewall with synthetic adversarial injections")

    # 3. 'demo' subcommand
    subparsers.add_parser("demo", help="Run live multi-agent enterprise workload simulator")

    # 4. 'version' subcommand
    subparsers.add_parser("version", help="Print RedHand SDK version")

    args = parser.parse_args(argv)

    if args.command == "version":
        print("RedHand ASPM Platform v0.1.0")
        return 0

    if args.command == "fuzz":
        print("🛡️  Running RedHand Synthetic Adversarial Injection Suite...\n")
        summary = run_adversarial_fuzz_suite()
        for res in summary.results:
            icon = "✓" if res.passed else "✗"
            status = "BLOCKED (PASS)" if res.verdict == "blocked" else "ALLOWED"
            print(f"  [{icon}] {res.attack_id:<15} {res.category:<30} {status:<15} ({res.latency_ms:.2f}ms)")

        print("\n" + "=" * 65)
        print(f"Total Tests:        {summary.total_tests}")
        print(f"Attack Block Rate:  {summary.attack_block_rate:.1f}%")
        print(f"Benign Pass Rate:   {summary.benign_pass_rate:.1f}%")
        print(f"p99 Latency SLA:    {summary.p99_latency_ms:.2f}ms (<50ms target)")
        print("=" * 65)
        return 0 if summary.failed_tests == 0 else 1

    if args.command == "demo":
        import asyncio
        import importlib.util

        demo_path = Path("examples/simulate_enterprise_workloads.py")
        if not demo_path.is_file():
            print("Error: examples/simulate_enterprise_workloads.py not found.")
            return 1

        spec = importlib.util.spec_from_file_location("simulate_workloads", demo_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            asyncio.run(mod.main())
            return 0
        return 1

    if args.command == "scan":
        target = Path(args.path)
        print(f"🔍 RedHand ASPM Static Guard Scanning: {target.resolve()}\n")

        findings = scan_directory(target) if target.is_dir() else scan_python_file(target)
        # Secrets in prompt and config files (RH-SEC-004). The findings hold file, line and kind only, never the value.
        secrets_result = scan_secrets(target)
        findings = findings + [f.to_scan_finding() for f in secrets_result.findings]
        for line in summary_lines(secrets_result):
            print(line)
        print()

        root = (target if target.is_dir() else target.parent).resolve()
        original_paths: dict[tuple[str, int, str], str] = {}

        def relative(path_text: str) -> str:
            """The path as a baseline entry names it: relative to the scanned folder when absolute, else as given, with forward slashes."""
            path = Path(path_text)
            if path.is_absolute():
                try:
                    return normalize_path(str(path.resolve().relative_to(root)))
                except ValueError:
                    return normalize_path(path_text)
            return normalize_path(path_text)

        normalized: list[ScanFinding] = []
        for f in findings:
            n = dataclasses.replace(f, file_path=relative(f.file_path))
            original_paths[(n.file_path, n.line_number, n.rule_id)] = f.file_path
            normalized.append(n)
        findings = normalized

        def line_of(finding: ScanFinding) -> str | None:
            """The text of the finding's line, only to fingerprint it. Never printed."""
            try:
                source = original_paths[(finding.file_path, finding.line_number, finding.rule_id)]
                return Path(source).read_text(encoding="utf-8").splitlines()[finding.line_number - 1]
            except (KeyError, OSError, UnicodeDecodeError, IndexError):
                return None

        if args.emit_baseline:
            out_path = Path(args.emit_baseline)
            if out_path.exists():
                print(f"Error: {out_path} already exists; the baseline is never overwritten.")
                return 2
            payload = {"version": 1, "entries": entries_for(findings, line_of)}
            out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote {len(payload['entries'])} baseline entries to {out_path}. Replace every TODO reason before using it: the loader refuses placeholders.")
            return 0

        accepted = 0
        stale = []
        if args.baseline:
            try:
                baseline = load_baseline(Path(args.baseline))
            except BaselineError as exc:
                print(f"Error: baseline refused: {exc}.")
                return 2
            applied = apply_baseline(findings, line_of, baseline)
            findings, accepted, stale = applied.new, applied.accepted, applied.stale
            noun = "finding" if accepted == 1 else "findings"
            print(f"Baseline: {accepted} {noun} accepted by the baseline ({args.baseline}).")
            for entry in stale:
                print("  [ERROR] RH-BASE-001: Baseline entry no longer matches")
                print(f"         Location: {entry.file} ({entry.rule}, {entry.unmatched} unmatched)")
                print("         Details:  Remove or reduce this entry: the code it accepted changed or was deleted.\n")

        if not findings and not stale:
            print(
                "✨ No findings in the Python agent tools or in the secret formats this scan knows. This is not a guarantee: "
                "it reads only the file types and key formats listed in `redhand scan --help`, and a clean result does not prove "
                "that no secret exists."
            )
            if args.sarif:
                export_sarif_v2([], args.sarif)
                print(f"📄 Exported clean SARIF report: {args.sarif}")
            return 0

        if not findings:
            return 1 if args.strict else 0
        print(f"Found {len(findings)} security finding(s):\n")
        for f in findings:
            badge = "ERROR" if f.severity == "error" else "WARN"
            print(f"  [{badge}] {f.rule_id}: {f.rule_name}")
            print(f"         Location: {f.file_path}:{f.line_number}")
            if f.tool_name:
                print(f"         Tool:     {f.tool_name}()")
            print(f"         Details:  {f.message}\n")

        if args.sarif:
            export_sarif_v2(findings, args.sarif)
            print(f"📄 Exported SARIF 2.1.0 report: {args.sarif}")

        if args.strict:
            has_errors = any(f.severity == "error" for f in findings) or bool(stale)
            if has_errors:
                print("❌ CI Gate Failed: High-severity agent security vulnerabilities detected.")
                return 1

        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
