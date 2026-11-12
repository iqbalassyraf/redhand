#!/usr/bin/env python3
"""
Measures how much time the RedHand gateway itself adds to a tool call (the "overhead" histogram, which excludes the upstream server's time),
by reading the gateway's /metrics before and after a batch of real calls. Standard library only. Prints numbers only: it never prints a key or token.

  export RH_AGENT_KEY=...        # an ACTIVE agent key (paste it into the terminal, never into chat)
  export RH_INTERNAL_TOKEN=...   # the gateway's internal service token (read it from Secret Manager, see docs/runbooks/latency-baseline.md)
  python3 scripts/latency_baseline.py --server deepwiki --tool read_wiki_structure --args '{"repoName": "facebook/react"}'

If a variable is missing you are asked for it with hidden input. Budget (CLAUDE.md section 8): p50 at most 10 ms, p99 at most 50 ms added by the gateway.
Caveat: the gateway takes this measurement BEFORE the call goes upstream, so it covers authentication, the passport lookup and the guardrails but NOT the work
done on the result afterwards (redaction, honeytoken scan, the Radar hand-off). Read it as "the gateway's checking cost", not the whole added time.
The percentiles are UPPER BOUNDS taken from histogram buckets (1, 2, 5, 10, 25, 50, 100, 250, 1000 ms), so "p50 <= 5 ms" means at most 5 ms.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from staging_agent import DEFAULT_CORE, DEFAULT_GATEWAY, Agent  # noqa: E402  (stdlib-only sibling script)

_BUCKET = re.compile(r'^redhand_gateway_overhead_ms_bucket\{le="([^"]+)"\} (\S+)$')
_STAGE_BUCKET = re.compile(r'^redhand_gateway_stage_ms_bucket\{stage="([a-z_]+)",le="([^"]+)"\} (\S+)$')
_STAGE_SUM = re.compile(r'^redhand_gateway_stage_ms_sum\{stage="([a-z_]+)"\} (\S+)$')
_STAGE_COUNT = re.compile(r'^redhand_gateway_stage_ms_count\{stage="([a-z_]+)"\} (\S+)$')
BUDGET_P50_MS, BUDGET_P99_MS = 10.0, 50.0


def parse_overhead(metrics_text: str) -> dict[str, object]:
    """The cumulative bucket counts, the sum and the count of the overhead histogram from Prometheus text."""
    buckets: list[tuple[float, float]] = []
    total_sum = count = 0.0
    for line in metrics_text.splitlines():
        m = _BUCKET.match(line)
        if m:
            edge = float("inf") if m.group(1) == "+Inf" else float(m.group(1))
            buckets.append((edge, float(m.group(2))))
        elif line.startswith("redhand_gateway_overhead_ms_sum "):
            total_sum = float(line.split()[1])
        elif line.startswith("redhand_gateway_overhead_ms_count "):
            count = float(line.split()[1])
    if not buckets:
        raise ValueError("no redhand_gateway_overhead_ms histogram in the metrics")
    if not count:
        count = max(c for _, c in buckets)
    return {"buckets": sorted(buckets), "sum": total_sum, "count": count}


def parse_stages(metrics_text: str) -> dict[str, dict[str, object]]:
    """Per-stage histograms (verify, context_hit, context_miss, guardrails, budget, ...) from Prometheus text. Empty on an older gateway."""
    stages: dict[str, dict[str, object]] = {}
    for line in metrics_text.splitlines():
        m = _STAGE_BUCKET.match(line)
        if m:
            entry = stages.setdefault(m.group(1), {"buckets": [], "sum": 0.0, "count": 0.0})
            edge = float("inf") if m.group(2) == "+Inf" else float(m.group(2))
            entry["buckets"].append((edge, float(m.group(3))))  # type: ignore[attr-defined]
            continue
        m = _STAGE_SUM.match(line)
        if m:
            stages.setdefault(m.group(1), {"buckets": [], "sum": 0.0, "count": 0.0})["sum"] = float(m.group(2))
            continue
        m = _STAGE_COUNT.match(line)
        if m:
            stages.setdefault(m.group(1), {"buckets": [], "sum": 0.0, "count": 0.0})["count"] = float(m.group(2))
    for entry in stages.values():
        entry["buckets"] = sorted(entry["buckets"])  # type: ignore[type-var]
    return stages


def summarise_stages(before: dict[str, dict[str, object]], after: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    """For each stage that ran between the two snapshots: how many times, and its p50 / p99 upper bounds and mean in ms."""
    empty: dict[str, object] = {"buckets": [], "sum": 0.0, "count": 0.0}
    out: dict[str, dict[str, object]] = {}
    for stage, now in after.items():
        try:
            out[stage] = summarise(before.get(stage, empty), now)
        except ValueError:
            continue  # the stage did not run during the test
    return out


def summarise(before: dict[str, object], after: dict[str, object]) -> dict[str, object]:
    """Percentile upper bounds and the mean for the calls between two snapshots."""
    b_buckets = dict(before["buckets"])  # type: ignore[arg-type]
    a_buckets = after["buckets"]
    delta = [(edge, max(0.0, c - b_buckets.get(edge, 0.0))) for edge, c in a_buckets]  # type: ignore[union-attr]
    n = max(c for _, c in delta)
    if n <= 0:
        raise ValueError("the gateway recorded no calls between the two snapshots")

    def upper(q: float) -> float:
        for edge, c in delta:
            if c >= q * n:
                return edge
        return float("inf")

    d_count = float(after["count"]) - float(before["count"])  # type: ignore[arg-type]
    mean = (float(after["sum"]) - float(before["sum"])) / d_count if d_count > 0 else float("nan")  # type: ignore[arg-type]
    c_100 = next((c for edge, c in delta if edge == 100.0), n)
    over_100 = max(0, int(round(n - c_100)))
    return {
        "calls": int(n),
        "p50_upper_ms": upper(0.50),
        "p99_upper_ms": upper(0.99),
        "mean_ms": round(mean, 3),
        "calls_over_100ms": over_100,
    }


SLOW_CALL_SECONDS = 1.5


def count_slow_calls(durations: list[float], threshold: float = SLOW_CALL_SECONDS) -> int:
    """How many calls took at least `threshold` seconds from start to finish (mostly the upstream tool). A call this slow can leave the
    gateway's passport entry expired for the next call, so this number is printed next to the cache misses."""
    return sum(1 for d in durations if d >= threshold)


def verdict(summary: dict[str, object]) -> str:
    p50, p99 = float(summary["p50_upper_ms"]), float(summary["p99_upper_ms"])  # type: ignore[arg-type]
    ok50, ok99 = p50 <= BUDGET_P50_MS, p99 <= BUDGET_P99_MS
    if ok50 and ok99:
        return "PASS: inside the budget (p50 <= 10 ms and p99 <= 50 ms)."
    parts = []
    if not ok50:
        parts.append(f"p50 is at most {p50:g} ms but the budget is {BUDGET_P50_MS:g} ms")
    if not ok99:
        parts.append(f"p99 is at most {p99:g} ms but the budget is {BUDGET_P99_MS:g} ms")
    return "OVER BUDGET: " + "; ".join(parts) + "."


def fetch_metrics(gateway: str, token: str) -> str:
    request = urllib.request.Request(f"{gateway}/metrics", headers={"Authorization": f"Bearer {token}", "User-Agent": "RedHand-LatencyBaseline/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        raise SystemExit(f"metrics refused (HTTP {error.code}): check RH_INTERNAL_TOKEN") from None
    except (urllib.error.URLError, TimeoutError) as error:
        raise SystemExit(f"could not reach the gateway: {error}") from None


def secret(name: str) -> str:
    return os.environ.get(name) or getpass.getpass(f"{name} (hidden): ")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--core", default=os.environ.get("RH_CORE_URL", DEFAULT_CORE))
    parser.add_argument("--gateway", default=os.environ.get("RH_GATEWAY_URL", DEFAULT_GATEWAY))
    parser.add_argument("--server", default="deepwiki")
    parser.add_argument("--tool", default="read_wiki_structure")
    parser.add_argument("--args", default='{"repoName": "facebook/react"}')
    parser.add_argument("--calls", type=int, default=200)
    parser.add_argument("--interval", type=float, default=0.2, help="seconds between calls (keep it gentle)")
    parser.add_argument("--out", help="also write the summary as JSON to this file")
    args = parser.parse_args()
    if not 20 <= args.calls <= 1000 or args.interval < 0.05:
        raise SystemExit("use 20 to 1000 calls and an interval of at least 0.05 s")
    token, key = secret("RH_INTERNAL_TOKEN"), secret("RH_AGENT_KEY")
    gateway = args.gateway.rstrip("/")
    agent = Agent("latency", args.core.rstrip("/"), gateway, args.server, key)
    ok, message = agent.ensure_token()
    if not ok:
        raise SystemExit(f"the agent key was refused: {message}")
    status, _ = agent.initialize()
    if status != 200:
        raise SystemExit(f"MCP initialize failed (HTTP {status})")
    before_text = fetch_metrics(gateway, token)
    before, before_stages = parse_overhead(before_text), parse_stages(before_text)
    arguments = json.loads(args.args)
    failures = 0
    durations: list[float] = []
    for i in range(args.calls):
        call_started = time.monotonic()
        status, body = agent.call_tool(args.tool, arguments)
        durations.append(time.monotonic() - call_started)
        if status != 200 or not isinstance(body, dict) or "result" not in body:
            failures += 1
            sys.stderr.write(f"\n[Call #{i+1} failed]: status={status}, body={str(body)[:150]}\n")
        time.sleep(args.interval)
    after_text = fetch_metrics(gateway, token)
    after, after_stages = parse_overhead(after_text), parse_stages(after_text)
    summary = summarise(before, after)
    summary.update({
        "requested_calls": args.calls, "failed_calls": failures,
        "calls_taking_1_5s_or_more_end_to_end": count_slow_calls(durations),
        "verdict": verdict(summary),
    })
    summary["stages"] = summarise_stages(before_stages, after_stages)  # which step the time went into (empty on an older gateway)
    print(json.dumps(summary, indent=2))
    print("\nWhat this means: the gateway adds at most p50 and p99 above, per call, not counting the upstream server.")
    print("Caveat: /metrics is read from one gateway instance; if Cloud Run started a second instance during the test the numbers are partial.")
    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
