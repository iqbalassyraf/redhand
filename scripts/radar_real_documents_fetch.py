#!/usr/bin/env python3
"""
Real documents for the M4.7b measurement (docs/security/m4-7b-split.md, docs/plans/phase4-m4-7b-quieter-rules.md): the DeepWiki answer for each
repository of the tuning set or the frozen set, fetched from the public DeepWiki MCP server (the same text the gateway sees through
`read_wiki_contents`), nothing else.

  fetch   Writes the TUNING set to a folder OUTSIDE this repository (decision P4-D10: third-party text is never committed). Refuses a folder
          inside the repository. Only the tuning documents may ever be opened by a person.
  count   Scans a set IN MEMORY and prints numbers only. For the FROZEN set it prints no repository name, no path and no text, so nobody can
          open a flagged document; it must be given --final, because the frozen set is measured once, after the rules are final.

  PYTHONPATH=. uv run python scripts/radar_real_documents_fetch.py fetch --out ~/radar-tuning-docs
  PYTHONPATH=. uv run python scripts/radar_real_documents_fetch.py count --set tuning
  PYTHONPATH=. uv run python scripts/radar_real_documents_fetch.py count --set frozen --final

Limits: a repository DeepWiki does not know, or a call that fails, is counted as unavailable (never as clean). Every document is assumed harmless, so a
strong finding counts as a false alarm; a document that really contains an attack would be counted against the check. The Radar reads at most 16 KiB
of a document (8 KiB from each end when longer), as in the gateway.
"""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Callable
import json
from pathlib import Path
import sys
import time
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentwall.src.bench.metrics import wilson  # noqa: E402
from agentwall.src.firewall import radar  # noqa: E402
from agentwall.src.firewall.radar_fingerprint import rules_fingerprint  # noqa: E402
from radar_real_documents_split import split  # noqa: E402

DEEPWIKI_URL = "https://mcp.deepwiki.com/mcp"
MAX_DOCUMENT_BYTES = 3 * 1024 * 1024
LONG_BYTES = 2048
REQUEST_TIMEOUT = httpx.Timeout(60.0, connect=10.0)
PAUSE_SECONDS = 0.4  # be a polite client of a public service
KINDS = ("injection", "output")


class DeepWikiError(Exception):
    """A call failed in a way that means this document is unavailable (never clean)."""


class DeepWikiClient:
    """A minimal client of DeepWiki's MCP server (streamable HTTP, JSON or event-stream answers)."""

    def __init__(self, http: httpx.Client | None = None, url: str = DEEPWIKI_URL) -> None:
        self._http = http or httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=False)
        self._url = url
        self._session: str | None = None
        self._next_id = 0
        self._ready = False

    def _post(self, body: dict[str, Any]) -> httpx.Response:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        try:
            return self._http.post(self._url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise DeepWikiError(type(exc).__name__) from None

    @staticmethod
    def _message(response: httpx.Response) -> dict[str, Any]:
        if response.status_code != 200:
            raise DeepWikiError(f"http {response.status_code}")
        if len(response.content) > MAX_DOCUMENT_BYTES:
            raise DeepWikiError("answer too large")
        text = response.text
        if "text/event-stream" in response.headers.get("content-type", ""):
            data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
            text = data[-1] if data else ""
        try:
            parsed = json.loads(text)
        except ValueError:
            raise DeepWikiError("not JSON") from None
        if not isinstance(parsed, dict):
            raise DeepWikiError("not an object")
        return parsed

    def _call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        response = self._post({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params})
        if method == "initialize":
            self._session = response.headers.get("Mcp-Session-Id") or self._session
        message = self._message(response)
        if "error" in message:
            raise DeepWikiError("server error")
        result = message.get("result")
        if not isinstance(result, dict):
            raise DeepWikiError("no result")
        return result

    def _ensure_ready(self) -> None:
        if self._ready:
            return
        self._call("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "redhand-m4-7b", "version": "0"}})
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self._ready = True

    def read_wiki_contents(self, repo: str) -> str:
        """The wiki text of one repository, or DeepWikiError."""
        self._ensure_ready()
        result = self._call("tools/call", {"name": "read_wiki_contents", "arguments": {"repoName": repo}})
        if result.get("isError"):
            raise DeepWikiError("tool error")
        parts = [c.get("text", "") for c in result.get("content", []) if isinstance(c, dict) and c.get("type") == "text" and isinstance(c.get("text"), str)]
        text = "\n".join(parts)
        if not text.strip():
            raise DeepWikiError("empty")
        return text


def inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def file_name(repo: str) -> str:
    return repo.replace("/", "__") + ".txt"


def scan_text(text: str) -> dict[str, Any]:
    """Strong findings per kind and the strong rules for one document, exactly as the gateway's scan would raise them. No text is kept."""
    report = radar.scan_result(text, radar.ScanContext(tool_names=frozenset()), frozenset(KINDS), radar.DEFAULT_DETECTORS)
    return {
        "strong": {k: any(f.kind == k and f.actionable for f in report.findings) for k in KINDS},
        "flagged": {k: any(f.kind == k for f in report.findings) for k in KINDS},
        "rules": sorted({f.rule_id for f in report.findings if f.actionable}),
        "long": len(text.encode("utf-8")) >= LONG_BYTES,
    }


def summarise(rows: list[dict[str, Any]], unavailable: int) -> dict[str, Any]:
    """Numbers only: counts, rates, the 95% upper bound of the strong rate (Wilson), the strong rules by number of documents."""
    n = len(rows)
    out: dict[str, Any] = {"documents_scanned": n, "unavailable": unavailable, "long_documents": sum(1 for r in rows if r["long"]),
                           "rules_fingerprint": rules_fingerprint(model_enabled=False)}
    for kind in KINDS:
        strong = sum(1 for r in rows if r["strong"][kind])
        low, high = wilson(strong, n) if n else (0.0, 1.0)
        out[kind] = {"flagged": sum(1 for r in rows if r["flagged"][kind]), "strong": strong, "strong_rate": round(strong / n, 4) if n else 0.0, "upper_bound_95": round(high, 4)}
    both = sum(1 for r in rows if any(r["strong"].values()))
    out["documents_with_any_strong_finding"] = both
    rules: Counter[str] = Counter(rule for r in rows for rule in r["rules"])
    out["strong_rules_by_documents"] = dict(sorted(rules.items()))
    return out


def run_fetch(client: DeepWikiClient, repos: list[str], out: Path, pause: float, sleep: Callable[[float], None]) -> dict[str, int]:
    out.mkdir(parents=True, exist_ok=True)
    saved = unavailable = 0
    for i, repo in enumerate(repos):
        if i:
            sleep(pause)
        try:
            text = client.read_wiki_contents(repo)
        except DeepWikiError:
            unavailable += 1
            continue
        (out / file_name(repo)).write_text(text, encoding="utf-8")
        saved += 1
    return {"saved": saved, "unavailable": unavailable}


def run_count(client: DeepWikiClient, repos: list[str], pause: float, sleep: Callable[[float], None]) -> tuple[list[dict[str, Any]], int, list[str]]:
    rows: list[dict[str, Any]] = []
    flagged_names: list[str] = []
    unavailable = 0
    for i, repo in enumerate(repos):
        if i:
            sleep(pause)
        try:
            text = client.read_wiki_contents(repo)
        except DeepWikiError:
            unavailable += 1
            continue
        row = scan_text(text)
        del text  # nothing of the document is kept
        rows.append(row)
        if any(row["strong"].values()):
            flagged_names.append(repo)
    return rows, unavailable, flagged_names


def main(argv: list[str] | None = None, client: DeepWikiClient | None = None, sleep: Callable[[float], None] = time.sleep) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="write the TUNING documents to a folder outside this repository")
    fetch.add_argument("--out", required=True, type=Path)
    count = sub.add_parser("count", help="scan a set in memory and print numbers only")
    count.add_argument("--set", choices=("tuning", "frozen"), required=True)
    count.add_argument("--final", action="store_true", help="required for the frozen set: it is measured once, after the rules are final")
    for p in (fetch, count):
        p.add_argument("--pause", type=float, default=PAUSE_SECONDS)
        p.add_argument("--limit", type=int, default=0, help="only the first N repositories (a smoke test)")
    args = parser.parse_args(argv)
    tuning, frozen = split()
    http_client = client or DeepWikiClient()

    if args.command == "fetch":
        if inside(args.out, ROOT):
            print("refused: the output folder is inside this repository; third-party text is never committed (P4-D10). Choose a folder outside it.", file=sys.stderr)
            return 2
        repos = tuning[: args.limit] if args.limit else tuning
        print(json.dumps(run_fetch(http_client, repos, args.out, args.pause, sleep)))
        return 0

    if args.set == "frozen" and not args.final:
        print("refused: the frozen set is measured once, after the rules are final. Add --final to do it.", file=sys.stderr)
        return 2
    repos = (tuning if args.set == "tuning" else frozen)
    repos = repos[: args.limit] if args.limit else repos
    rows, unavailable, flagged = run_count(http_client, repos, args.pause, sleep)
    summary = summarise(rows, unavailable)
    summary["set"] = args.set
    if args.set == "tuning":
        summary["strong_repositories"] = sorted(flagged)  # names of TUNING documents only, so a person can open them
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
