#!/usr/bin/env python3
"""
Model-proxy prototype benchmark (Phase 4.5 B5, docs/adr/0025-model-proxy-prototype.md): what the gateway adds to a model call, on real processes.

Starts core, the gateway with the proxy enabled, and a FAKE provider (examples/fake_model_provider.py) on loopback, registers an agent whose passport covers one model,
then compares the same requests sent straight to the fake provider and through the gateway:

  non-stream   N sequential requests, provider answers at once (isolates the gateway's own cost) and after a realistic delay;
  stream       time to first byte and the gaps between events, for a stream of 50 events 20 ms apart;
  concurrent   many streams at once: completion, errors, the gateway's memory before and after.

Local loopback only, a fake provider, no real key, no network. The numbers say what the PROXY costs on this machine; they say nothing about a real provider or network.
  uv run python scripts/benchmark_model_proxy.py --out docs/security/measurements/2026-11-17-model-proxy-prototype.md
"""

from __future__ import annotations

import argparse
import asyncio
import os
import platform
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import revocation_drill as drill  # noqa: E402  (a script next to this one)

MODEL = "claude-sonnet-5-5"
BODY = {"model": MODEL, "max_tokens": 100, "messages": [{"role": "user", "content": "hello"}]}


def pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]


def summary(values: list[float]) -> str:
    ms = [v * 1000 for v in values]
    return f"{statistics.median(ms):.2f} / {pct(ms, 0.95):.2f} / {pct(ms, 0.99):.2f}"


@dataclass
class Bench(drill.Stack):
    provider_port: int = field(default_factory=drill.free_port)
    provider_latency_ms: int = 0

    def start(self, name: str) -> None:
        if name != "provider":
            return super().start(name)
        env = {**os.environ, "FAKE_PROVIDER_LATENCY_MS": str(self.provider_latency_ms)}
        cmd = [sys.executable, "-m", "uvicorn", "examples.fake_model_provider:app", "--port", str(self.provider_port), "--log-level", "warning"]
        self.procs[name] = subprocess.Popen(cmd, cwd=drill.ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return None


def rss_mb(pid: int) -> float:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024
    return 0.0


def up(latency_ms: int) -> tuple[Bench, str]:
    stack = Bench()
    stack.provider_latency_ms = latency_ms
    stack.gateway_env = {
        "AGENTWALL_MODEL_PROXY_ENABLED": "true", "AGENTWALL_MODEL_PROXY_ANTHROPIC_KEY": "fake-provider-key-for-the-benchmark",
        "AGENTWALL_MODEL_PROXY_ANTHROPIC_URL": f"http://127.0.0.1:{stack.provider_port}",
    }
    stack.start("provider")
    stack.start("core")
    stack.wait_healthy(f"{stack.core}/health")
    stack.wait_healthy(f"http://127.0.0.1:{stack.provider_port}/health")
    stack.start("gateway")
    stack.wait_healthy(f"{stack.gateway}/health")
    op = drill.Operator(stack)
    response = op.post("/v1/passports", {"name": "bench-agent", "framework": "custom", "scopes": [{"server": "model", "tool": MODEL}]})
    key = response.json()["agent_key"]
    caller = drill.Caller(stack, key)
    if caller.exchange() != 200:
        raise RuntimeError("token exchange failed")
    return stack, caller.token


async def non_stream(stack: Bench, token: str, count: int) -> tuple[list[float], list[float]]:
    direct_url = f"http://127.0.0.1:{stack.provider_port}/v1/messages"
    proxy_url = f"{stack.gateway}/v1/model/anthropic/v1/messages"
    direct: list[float] = []
    proxied: list[float] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for _ in range(20):  # warm up connections, JIT, caches
            await client.post(proxy_url, json=BODY, headers={"Authorization": f"Bearer {token}"})
            await client.post(direct_url, json=BODY)
        for _ in range(count):
            t = time.perf_counter()
            r = await client.post(direct_url, json=BODY)
            direct.append(time.perf_counter() - t)
            assert r.status_code == 200
            t = time.perf_counter()
            r = await client.post(proxy_url, json=BODY, headers={"Authorization": f"Bearer {token}"})
            proxied.append(time.perf_counter() - t)
            assert r.status_code == 200, r.text
    return direct, proxied


async def one_stream(client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> tuple[float, list[float], float, int]:
    started = time.perf_counter()
    first = 0.0
    last = started
    gaps: list[float] = []
    size = 0
    async with client.stream("POST", url, json={**BODY, "stream": True}, headers=headers) as response:
        if response.status_code != 200:
            raise RuntimeError(f"stream answered {response.status_code}")
        async for chunk in response.aiter_raw():
            now = time.perf_counter()
            if not first:
                first = now - started
            else:
                gaps.append(now - last)
            last = now
            size += len(chunk)
    return first, gaps, time.perf_counter() - started, size


async def streaming(stack: Bench, token: str, count: int) -> dict[str, Any]:
    direct_url = f"http://127.0.0.1:{stack.provider_port}/v1/messages"
    proxy_url = f"{stack.gateway}/v1/model/anthropic/v1/messages"
    out: dict[str, Any] = {"direct": ([], [], [], []), "proxy": ([], [], [], [])}
    async with httpx.AsyncClient(timeout=60.0) as client:
        await one_stream(client, proxy_url, {"Authorization": f"Bearer {token}"})
        for _ in range(count):
            for label, url, headers in (("direct", direct_url, {}), ("proxy", proxy_url, {"Authorization": f"Bearer {token}"})):
                first, gaps, total, size = await one_stream(client, url, headers)
                out[label][0].append(first)
                out[label][1].extend(gaps)
                out[label][2].append(total)
                out[label][3].append(size)
    return out


async def concurrent(stack: Bench, token: str, streams: int) -> dict[str, Any]:
    proxy_url = f"{stack.gateway}/v1/model/anthropic/v1/messages"
    pid = stack.procs["gateway"].pid
    before = rss_mb(pid)
    errors = 0
    started = time.perf_counter()
    async with httpx.AsyncClient(timeout=120.0, limits=httpx.Limits(max_connections=streams + 5)) as client:
        results = await asyncio.gather(*[one_stream(client, proxy_url, {"Authorization": f"Bearer {token}"}) for _ in range(streams)], return_exceptions=True)
    errors = sum(1 for r in results if isinstance(r, BaseException))
    elapsed = time.perf_counter() - started
    return {"streams": streams, "errors": errors, "seconds": elapsed, "rss_before": before, "rss_after": rss_mb(pid)}


def run(count: int, streams: int) -> str:
    lines: list[str] = []
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=drill.ROOT, capture_output=True, text=True).stdout.strip() or "unknown"
    lines += ["# Model proxy prototype: measured overhead (local, fake provider)", "",
              f"- Run: {time.strftime('%Y-%m-%d %H:%M', time.gmtime())} UTC; commit `{commit}`; `scripts/benchmark_model_proxy.py`; {count} paired requests per row.",
              f"- Machine: {platform.platform()}, Python {platform.python_version()}, {os.cpu_count()} CPUs. **Loopback, fake provider, no real key.** "
              "The numbers are what the proxy ADDS; a real provider and network add their own time on top, and the proxy's share of the total would be small.",
              "- Budget being tested (CLAUDE.md section 8, written for the tool route): gateway added latency p50 at most 10 ms, p99 at most 50 ms.", ""]
    for latency in (0, 100):
        stack, token = up(latency)
        try:
            direct, proxied = asyncio.run(non_stream(stack, token, count))
            overhead = [max(0.0, p - d) for p, d in zip(proxied, direct)]
            lines += [f"## Non-stream, provider answers after {latency} ms", "", "| | p50 / p95 / p99 (ms) |", "|---|---|",
                      f"| direct to the provider | {summary(direct)} |", f"| through the gateway | {summary(proxied)} |",
                      f"| **gateway overhead (paired, per request)** | **{summary(overhead)}** |", ""]
            if latency == 0:
                s = asyncio.run(streaming(stack, token, max(10, count // 10)))
                d, p = s["direct"], s["proxy"]
                same = d[3][0] == p[3][0]
                lines += ["## Stream: 50 events, 20 ms apart", "", "| | direct | through the gateway |", "|---|---|---|",
                          f"| time to first byte, p50 / p95 / p99 (ms) | {summary(d[0])} | {summary(p[0])} |",
                          f"| gap between events, p50 / p95 / p99 (ms) | {summary(d[1])} | {summary(p[1])} |",
                          f"| whole stream, p50 / p95 / p99 (ms) | {summary(d[2])} | {summary(p[2])} |",
                          f"| bytes received (same?) | {d[3][0]} | {p[3][0]} ({'identical' if same else 'DIFFERENT'}) |", ""]
                c = asyncio.run(concurrent(stack, token, streams))
                lines += [f"## {c['streams']} streams at once", "",
                          f"- Completed with {c['errors']} errors in {c['seconds']:.2f} s (each stream alone takes about 1.1 s).",
                          f"- Gateway memory (RSS): {c['rss_before']:.0f} MB before, {c['rss_after']:.0f} MB after.", ""]
        finally:
            stack.down()
    lines += ["## Not measured", "- A real provider, TLS to the provider, network distance, several gateway instances, prompt and completion inspection (not built), "
              "the per-tenant key store (not built), reporting usage to core (not built).", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--requests", type=int, default=300)
    parser.add_argument("--streams", type=int, default=100)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    text = run(args.requests, args.streams)
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
