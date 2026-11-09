#!/usr/bin/env python3
"""
Real-life proof for the Radar's evidence counting (Phase 4 M4.6b). Standard library only. Prints numbers only: never a key, a token or document text.

It plays a real agent against the STAGING gateway: it asks a real third-party MCP server (DeepWiki, already registered on staging) for the wiki of many
well-known public repositories. Those answers are real, long, third-party documents that nobody wrote for our tests. Then it reads the gateway's /metrics
before and after and checks, with exact numbers, that:

  1. every result the gateway returned was scanned (scans ok = results received),
  2. nothing was lost on the way (dropped = 0, errors = 0),
  3. the evidence counts reached core (count reports ok > 0, failed = 0, after the one-minute flush),
  4. how many flagged results the checks raised on real documents (the false alarm picture nobody had before).

The OWNER then compares the same numbers on the Radar page (core's side): "Your traffic, last 7 days" must show the same increase in results scanned.

  export RH_AGENT_KEY=...        # an ACTIVE agent key allowed to call deepwiki read_wiki_contents (paste into the terminal, never into chat)
  export RH_INTERNAL_TOKEN=...   # the gateway's internal service token (read it from Secret Manager, see docs/runbooks/latency-baseline.md)
  python3 scripts/radar_real_life_proof.py --calls 120

Use it while nobody else is calling through the staging gateway, otherwise the before/after difference includes their traffic. It is gentle on the third-party
server (one call every 0.5 s by default) and refuses to send more than 300 calls. It changes nothing in RedHand except adding traffic and counts.
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
from typing import Callable
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from staging_agent import DEFAULT_CORE, DEFAULT_GATEWAY, Agent  # noqa: E402  (stdlib-only sibling script)

LONG_BYTES = 2048  # the same "long, realistic text" bar as the block gate (rule G5)
MAX_CALLS = 300
FLUSH_WAIT_SECONDS = 75  # the gateway sends its counts about once a minute

# Well-known public repositories (real, long wiki pages). A repository DeepWiki does not know simply returns an error and is counted as such.
REPOS = (
    "facebook/react", "vuejs/core", "angular/angular", "sveltejs/svelte", "vercel/next.js", "nodejs/node", "denoland/deno", "oven-sh/bun",
    "microsoft/vscode", "microsoft/TypeScript", "golang/go", "rust-lang/rust", "python/cpython", "django/django", "pallets/flask",
    "fastapi/fastapi", "encode/starlette", "encode/httpx", "psf/requests", "numpy/numpy", "pandas-dev/pandas", "scikit-learn/scikit-learn",
    "pytorch/pytorch", "tensorflow/tensorflow", "huggingface/transformers", "langchain-ai/langchain", "openai/openai-python",
    "kubernetes/kubernetes", "docker/compose", "moby/moby", "hashicorp/terraform", "prometheus/prometheus", "grafana/grafana", "redis/redis",
    "postgres/postgres", "elastic/elasticsearch", "apache/kafka", "apache/spark", "apache/airflow", "ansible/ansible", "nginx/nginx",
    "git/git", "neovim/neovim", "vim/vim", "tmux/tmux", "ohmyzsh/ohmyzsh", "home-assistant/core", "etcd-io/etcd", "istio/istio",
    "envoyproxy/envoy", "cilium/cilium", "traefik/traefik", "caddyserver/caddy", "gin-gonic/gin", "labstack/echo", "spf13/cobra",
    "tokio-rs/tokio", "serde-rs/serde", "clap-rs/clap", "BurntSushi/ripgrep", "sharkdp/bat", "junegunn/fzf", "jqlang/jq", "curl/curl",
    "openssl/openssl", "expressjs/express", "koajs/koa", "fastify/fastify", "nestjs/nest", "prisma/prisma", "drizzle-team/drizzle-orm",
    "typeorm/typeorm", "sequelize/sequelize", "axios/axios", "lodash/lodash", "moment/moment", "date-fns/date-fns", "webpack/webpack",
    "vitejs/vite", "rollup/rollup", "evanw/esbuild", "babel/babel", "eslint/eslint", "prettier/prettier", "jestjs/jest", "vitest-dev/vitest",
    "cypress-io/cypress", "microsoft/playwright", "puppeteer/puppeteer", "tailwindlabs/tailwindcss", "mui/material-ui", "ant-design/ant-design",
    "shadcn-ui/ui", "reduxjs/redux", "reduxjs/redux-toolkit", "TanStack/query", "pmndrs/zustand", "remix-run/react-router",
    "storybookjs/storybook", "expo/expo", "facebook/react-native", "flutter/flutter", "dart-lang/sdk", "JetBrains/kotlin", "apple/swift",
    "dotnet/runtime", "dotnet/aspnetcore", "spring-projects/spring-boot", "gradle/gradle", "elixir-lang/elixir", "phoenixframework/phoenix",
    "rails/rails", "laravel/framework", "symfony/symfony", "ruby/ruby", "php/php-src", "JuliaLang/julia", "ziglang/zig", "nim-lang/Nim",
    "ocaml/ocaml", "bazelbuild/bazel", "protocolbuffers/protobuf", "grpc/grpc", "nats-io/nats-server", "minio/minio", "gitea/gitea",
    "supabase/supabase", "appwrite/appwrite", "strapi/strapi", "directus/directus", "n8n-io/n8n", "langgenius/dify", "ollama/ollama",
    "ggerganov/llama.cpp", "AUTOMATIC1111/stable-diffusion-webui", "modelcontextprotocol/servers", "modelcontextprotocol/python-sdk",
)

_SCANS = re.compile(r'^redhand_gateway_radar_scans_total\{outcome="([a-z]+)"\} (\S+)$')
_FINDINGS = re.compile(r'^redhand_gateway_radar_findings_total\{kind="([a-z]+)"\} (\S+)$')
_COUNT_REPORTS = re.compile(r'^redhand_gateway_radar_count_reports_total\{outcome="([a-z]+)"\} (\S+)$')
_REPORTS = re.compile(r'^redhand_gateway_radar_reports_total\{outcome="([a-z]+)"\} (\S+)$')


def parse_counters(metrics_text: str) -> dict[str, dict[str, float]]:
    """The Radar counters from Prometheus text, by family then label. A family that is missing (an older gateway) is simply empty."""
    out: dict[str, dict[str, float]] = {"scans": {}, "findings": {}, "count_reports": {}, "reports": {}}
    for line in metrics_text.splitlines():
        for family, pattern in (("scans", _SCANS), ("findings", _FINDINGS), ("count_reports", _COUNT_REPORTS), ("reports", _REPORTS)):
            m = pattern.match(line)
            if m:
                out[family][m.group(1)] = float(m.group(2))
    return out


def delta(before: dict[str, dict[str, float]], after: dict[str, dict[str, float]]) -> dict[str, dict[str, float]]:
    """After minus before, per label (a label that did not exist before counts from zero)."""
    return {
        family: {label: after[family].get(label, 0.0) - before[family].get(label, 0.0) for label in sorted(set(after[family]) | set(before[family]))}
        for family in after
    }


def result_text_bytes(body: object) -> int | None:
    """Size in bytes of the text a tools/call answered with, or None when the call returned no result (an error, or a malformed answer)."""
    if not isinstance(body, dict) or not isinstance(body.get("result"), dict):
        return None
    content = body["result"].get("content")
    if not isinstance(content, list):
        return 0
    return sum(len(str(part.get("text", "")).encode("utf-8")) for part in content if isinstance(part, dict))


def judge(calls: int, received: int, long_results: int, moved: dict[str, dict[str, float]]) -> list[tuple[str, bool, str]]:
    """Plain checks, each (name, passed, detail). Only exact matches pass: 'about the same' is not proof."""
    scans_ok = moved["scans"].get("ok", 0.0)
    lost = moved["scans"].get("dropped", 0.0) + moved["scans"].get("error", 0.0)
    count_ok, count_bad = moved["count_reports"].get("ok", 0.0), moved["count_reports"].get("failed", 0.0) + moved["count_reports"].get("refused", 0.0)
    # One result is scanned once per switched-on check in one background pass, so "scans ok" counts results, not checks.
    return [
        ("every result was scanned", scans_ok == received, f"{int(scans_ok)} scans ok for {received} results received"),
        ("nothing was lost", lost == 0, f"{int(lost)} dropped or failed scans"),
        ("counts reached core", count_ok >= 1 and count_bad == 0, f"{int(count_ok)} count reports ok, {int(count_bad)} refused or failed"),
        ("real long documents were used", long_results >= max(1, received // 2),
         f"{long_results} of {received} results are {LONG_BYTES // 1024} KiB or longer"),
        ("enough calls to mean something", received >= 100, f"{received} results received (at least 100 needed for a 3% false alarm bound)"),
        ("no call failed", received == calls, f"{received} of {calls} calls returned a result"),
    ]


def fetch_metrics(gateway: str, token: str) -> str:
    request = urllib.request.Request(gateway + "/metrics", headers={"Authorization": f"Bearer {token}", "User-Agent": "RedHand-RealLifeProof/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return str(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError) as error:
        raise SystemExit(f"could not read the gateway /metrics: {error}") from None


def keepalive_wait(fetch: Callable[[], str], seconds: float, interval: float = 10.0,
                   sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> str:
    """
    Waits `seconds` while reading /metrics every `interval` and returns the LAST reading. Cloud Run pauses background timers while no request is running, so the
    gateway's counts report may only fire if something keeps talking to it; a silent sleep could read the metrics before the report was ever sent.
    """
    deadline = clock() + seconds
    text = fetch()
    while clock() < deadline:
        sleep(min(interval, max(0.0, deadline - clock())))
        text = fetch()
    return text


def secret(name: str) -> str:
    return os.environ.get(name) or getpass.getpass(f"{name} (hidden): ")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--core", default=os.environ.get("RH_CORE_URL", DEFAULT_CORE))
    parser.add_argument("--gateway", default=os.environ.get("RH_GATEWAY_URL", DEFAULT_GATEWAY))
    parser.add_argument("--server", default="deepwiki")
    parser.add_argument("--tool", default="read_wiki_contents")
    parser.add_argument("--calls", type=int, default=120)
    parser.add_argument("--interval", type=float, default=0.5, help="seconds between calls (be gentle with the third-party server)")
    parser.add_argument("--wait", type=int, default=FLUSH_WAIT_SECONDS, help="seconds to wait for the gateway's one-minute count report")
    parser.add_argument("--out", help="also write the result as JSON to this file")
    args = parser.parse_args()
    if not 20 <= args.calls <= min(MAX_CALLS, len(REPOS)) or args.interval < 0.2 or args.wait < 0:
        raise SystemExit(f"use 20 to {min(MAX_CALLS, len(REPOS))} calls, an interval of at least 0.2 s and a wait of 0 or more")
    token, key = secret("RH_INTERNAL_TOKEN"), secret("RH_AGENT_KEY")
    gateway = args.gateway.rstrip("/")
    agent = Agent("real-life-proof", args.core.rstrip("/"), gateway, args.server, key)
    ok, message = agent.ensure_token()
    if not ok:
        raise SystemExit(f"the agent key was refused: {message}")
    status, _ = agent.initialize()
    if status != 200:
        raise SystemExit(f"MCP initialize failed (HTTP {status})")

    before = parse_counters(fetch_metrics(gateway, token))
    received = long_results = total_bytes = 0
    failures: list[str] = []
    for i, repo in enumerate(REPOS[: args.calls]):
        status, body = agent.call_tool(args.tool, {"repoName": repo})
        size = result_text_bytes(body)
        if status == 200 and size is not None:
            received += 1
            total_bytes += size
            long_results += 1 if size >= LONG_BYTES else 0
        else:
            failures.append(f"call {i + 1} ({repo}): HTTP {status}")
        time.sleep(args.interval)
    print(f"Made {args.calls} calls; {received} returned a result ({total_bytes // 1024} KiB of real documents in total). Waiting {args.wait} s for the counts report...")
    after = parse_counters(keepalive_wait(lambda: fetch_metrics(gateway, token), args.wait))
    moved = delta(before, after)
    checks = judge(args.calls, received, long_results, moved)

    print("\nWhat the gateway counted (difference during this test):")
    for family, label in (("scans", "scans by outcome"), ("findings", "findings by check, before the repeat limit"), ("count_reports", "evidence-count reports"), ("reports", "findings reports")):
        print(f"  {label}: " + (", ".join(f"{k}={int(v)}" for k, v in moved[family].items() if v) or "none"))
    print("\nVerdict:")
    for name, passed, detail in checks:
        print(f"  {'GOOD' if passed else 'BAD '} {name}: {detail}")
    for line in failures[:10]:
        print(f"  note: {line}")
    print(
        f"\nNow open the Radar page and read 'Your traffic, last 7 days': the results scanned must have grown by exactly {received} for each check that is on Watch, "
        "and 'strong findings' is the number of real documents a check flagged. Review each strong finding as Real or False alarm, then read the false alarm figure."
    )
    summary = {"calls": args.calls, "received": received, "long_results": long_results, "bytes": total_bytes, "moved": moved,
               "checks": [{"name": n, "passed": p, "detail": d} for n, p, d in checks], "failures": failures}
    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0 if all(p for _, p, _ in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
