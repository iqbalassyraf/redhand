#!/usr/bin/env python3
"""
Revocation and failure drill: real processes, real HTTP, measured numbers (CLAUDE.md sections 4.3, 4.5 and 8; release-readiness 3.5).

Starts three processes on free local ports: redhand-core (development mode, in-memory store), a demo MCP server and the AgentWall gateway with its real
passport-cache settings. Then, with an agent calling a tool every ~50 ms through the gateway:

  freeze, revoke, freeze-all   the time from the operator's "200 OK" to the agent's first refused call, over N trials each, against the 5 s promise,
                               and whether any call was allowed after the first refusal;
  core stopped (SIGSTOP)       the gateway cannot reach core: calls must be refused, and allowed again after core resumes (SIGCONT);
  core killed                  the same with the process gone;
  upstream killed              an MCP server that vanishes gives an error, never an allow, and the gateway stays responsive.

Everything is local: loopback only, no network beyond it. The numbers describe this machine and this commit, not staging or production.

  uv run python scripts/revocation_drill.py                    # 20 trials each, prints a report
  uv run python scripts/revocation_drill.py --out docs/security/measurements/NAME.md
  uv run python scripts/revocation_drill.py --trials 3 --quick   # what CI runs
Exit code 0 only when every check held; 1 otherwise (a breach of the SLO or any allow after a refusal).
"""

from __future__ import annotations

import argparse
import contextlib
import os
import platform
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
SLO_SECONDS = 5.0
POLL_INTERVAL = 0.05
SERVICE_TOKEN = "drill-service-token-" + "0123456789abcdef" * 2


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class Stack:
    core_port: int = field(default_factory=free_port)
    gateway_port: int = field(default_factory=free_port)
    upstream_port: int = field(default_factory=free_port)
    procs: dict[str, subprocess.Popen[bytes]] = field(default_factory=dict)

    @property
    def core(self) -> str:
        return f"http://127.0.0.1:{self.core_port}"

    @property
    def gateway(self) -> str:
        return f"http://127.0.0.1:{self.gateway_port}"

    def start(self, name: str) -> None:
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}
        if name == "core":
            env.update(ENVIRONMENT="development", ALLOW_INSECURE_MCP_URLS="true", INTERNAL_SERVICE_TOKEN=SERVICE_TOKEN)
            cmd = [sys.executable, "-m", "uvicorn", "redhand_core.main:app", "--port", str(self.core_port), "--log-level", "warning"]
        elif name == "upstream":
            cmd = [sys.executable, "-m", "uvicorn", "examples.demo_mcp_server:app", "--port", str(self.upstream_port), "--log-level", "warning"]
        else:
            env.update(AGENTWALL_ENVIRONMENT="development", AGENTWALL_CORE_URL=self.core, AGENTWALL_CORE_SERVICE_TOKEN=SERVICE_TOKEN,
                       AGENTWALL_ALLOW_INSECURE_UPSTREAMS="true")
            cmd = [sys.executable, "-m", "uvicorn", "agentwall.src.main:app", "--port", str(self.gateway_port), "--log-level", "warning"]
        self.procs[name] = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def wait_healthy(self, url: str, timeout: float = 45.0, post: bool = False) -> None:
        """Waits for a 200 (GET), or for any answer below 500 to a JSON-RPC POST (the demo MCP server has no health route)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with contextlib.suppress(httpx.HTTPError):
                if post:
                    if httpx.post(url, json={"jsonrpc": "2.0", "id": 0, "method": "ping"}, timeout=1.0).status_code < 500:
                        return
                elif httpx.get(url, timeout=1.0).status_code == 200:
                    return
            time.sleep(0.2)
        raise RuntimeError(f"{url} did not become healthy in {timeout:.0f} s")

    def up(self) -> None:
        self.start("core")
        self.start("upstream")
        self.wait_healthy(f"{self.core}/health")
        self.wait_healthy(f"http://127.0.0.1:{self.upstream_port}/mcp", post=True)
        self.start("gateway")
        self.wait_healthy(f"{self.gateway}/health")

    def down(self) -> None:
        for proc in self.procs.values():
            with contextlib.suppress(ProcessLookupError):
                proc.send_signal(signal.SIGCONT)
                proc.terminate()
        for proc in self.procs.values():
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=8)
            if proc.poll() is None:
                proc.kill()


class Operator:
    def __init__(self, stack: Stack) -> None:
        self.stack = stack
        self.http = httpx.Client(timeout=10.0)
        token = self.http.post(f"{stack.core}/v1/dev/login", json={"user": "owner"}).json()["access_token"]
        self.headers = {"Authorization": f"Bearer {token}"}

    def post(self, path: str, body: dict[str, Any]) -> httpx.Response:
        return self.http.post(f"{self.stack.core}{path}", json=body, headers=self.headers)

    def register_server(self) -> None:
        response = self.post("/v1/mcp-servers", {"slug": "xero", "name": "Demo", "url": f"http://127.0.0.1:{self.stack.upstream_port}/mcp"})
        if response.status_code not in (200, 201, 409):
            raise RuntimeError(f"could not register the MCP server: {response.status_code}")

    def new_agent(self, label: str) -> tuple[str, str]:
        response = self.post("/v1/passports", {"name": label, "framework": "custom", "scopes": [{"server": "xero", "tool": "list_invoices"}]})
        if response.status_code != 201:
            raise RuntimeError(f"could not register an agent: {response.status_code}")
        body = response.json()
        return str(body["passport"]["id"]), str(body["agent_key"])


class Caller:
    """An agent: exchanges its key for a token, then calls a tool through the gateway as fast as asked."""

    def __init__(self, stack: Stack, agent_key: str) -> None:
        self.stack = stack
        self.key = agent_key
        self.http = httpx.Client(timeout=httpx.Timeout(6.0, connect=2.0))
        self.token = ""

    def exchange(self) -> int:
        response = self.http.post(f"{self.stack.core}/v1/agent-auth/token", headers={"Authorization": f"Bearer {self.key}"})
        if response.status_code == 200:
            self.token = str(response.json()["access_token"])
        return response.status_code

    def call(self, tool: str = "list_invoices") -> tuple[int, float]:
        """(HTTP status, seconds the call took). A transport failure is reported as status 0."""
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {}}}
        started = time.monotonic()
        try:
            response = self.http.post(f"{self.stack.gateway}/mcp/xero", json=body, headers={"Authorization": f"Bearer {self.token}"})
            return response.status_code, time.monotonic() - started
        except httpx.HTTPError:
            return 0, time.monotonic() - started


@dataclass
class Poll:
    """Calls in a background thread and keeps (monotonic time, status) for every answer."""

    caller: Caller
    interval: float = POLL_INTERVAL
    log: list[tuple[float, int]] = field(default_factory=list)
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None

    def __enter__(self) -> Poll:
        def run() -> None:
            while not self.stop.is_set():
                status, _ = self.caller.call()
                self.log.append((time.monotonic(), status))
                time.sleep(self.interval)

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=10)

    def wait_for(self, predicate: Any, since: float, timeout: float) -> float | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for at, status in list(self.log):
                if at >= since and predicate(status):
                    return at
            time.sleep(0.02)
        return None


ALLOWED = 200


@dataclass
class Measure:
    name: str
    seconds: list[float] = field(default_factory=list)
    allowed_after_refusal: int = 0
    never_refused: int = 0

    def row(self) -> str:
        if not self.seconds:
            return f"| {self.name} | 0 | n/a | n/a | n/a | {self.never_refused} | {self.allowed_after_refusal} |"
        ordered = sorted(self.seconds)
        p95 = ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))]
        return (f"| {self.name} | {len(ordered)} | {statistics.median(ordered):.2f} | {p95:.2f} | {ordered[-1]:.2f} | "
                f"{self.never_refused} | {self.allowed_after_refusal} |")

    @property
    def held(self) -> bool:
        return not self.never_refused and not self.allowed_after_refusal and all(s <= SLO_SECONDS for s in self.seconds)


def warm(caller: Caller) -> None:
    """Exchanges the key and makes sure the gateway has the passport cached and allows the call before the action under test."""
    status = caller.exchange()
    if status != 200:
        raise RuntimeError(f"token exchange answered {status}")
    for _ in range(40):
        if caller.call()[0] == ALLOWED:
            time.sleep(0.3)
            return
        time.sleep(0.1)
    raise RuntimeError("the agent's call was never allowed; the stack is not set up correctly")


def trial(stack: Stack, op: Operator, action: str, index: int, interval: float = POLL_INTERVAL) -> tuple[float | None, int]:
    """One action on a warm agent; returns (seconds until the first refusal, allowed answers seen after it)."""
    agent_id, key = op.new_agent(f"drill-{action}-{index}")
    caller = Caller(stack, key)
    warm(caller)
    with Poll(caller, interval) as poll:
        time.sleep(max(0.4, 2 * interval))  # steady state: several allowed calls first
        if action == "freeze":
            response = op.post(f"/v1/passports/{agent_id}/freeze", {"reason": "drill"})
        elif action == "revoke":
            response = op.post(f"/v1/passports/{agent_id}/revoke", {"reason": "drill", "confirm": True})
        else:
            response = op.post("/v1/passports/freeze-all", {"reason": "drill", "confirm": True})
        done = time.monotonic()
        if response.status_code != 200:
            raise RuntimeError(f"{action} answered {response.status_code}: {response.text[:120]}")
        refused_at = poll.wait_for(lambda status: status != ALLOWED, since=done, timeout=SLO_SECONDS + 5)
        time.sleep(1.5)  # keep calling: an allow after the first refusal is a breach
    if refused_at is None:
        return None, 0
    later = [s for at, s in poll.log if at > refused_at and s == ALLOWED]
    return max(0.0, refused_at - done), len(later)


def measure_actions(stack: Stack, op: Operator, trials: int) -> list[Measure]:
    """Busy agents (a call every 50 ms) and sparse ones (a call a second): the gateway reuses a passport lookup for a short time, so how long a
    freeze takes to bite can depend on how often the agent calls."""
    out: list[Measure] = []
    plan = [("freeze", POLL_INTERVAL), ("revoke", POLL_INTERVAL), ("freeze-all", POLL_INTERVAL), ("freeze", 1.0), ("revoke", 1.0)]
    for action, interval in plan:
        m = Measure(action if interval == POLL_INTERVAL else f"{action}, agent calls once a second")
        for i in range(trials if interval == POLL_INTERVAL else max(3, trials // 2)):
            seconds, late = trial(stack, op, action, i, interval)
            if seconds is None:
                m.never_refused += 1
            else:
                m.seconds.append(seconds)
            m.allowed_after_refusal += late
        out.append(m)
    return out


@dataclass
class Outcome:
    name: str
    held: bool
    detail: str

    def row(self) -> str:
        return f"| {self.name} | {'held' if self.held else 'BROKEN'} | {self.detail} |"


def core_outage(stack: Stack, op: Operator, mode: str) -> Outcome:
    """Core paused (it accepts connections but never answers) or killed: the gateway must refuse once its short cache expires, and recover afterwards."""
    _, key = op.new_agent(f"drill-core-{mode}")
    caller = Caller(stack, key)
    warm(caller)
    proc = stack.procs["core"]
    with Poll(caller) as poll:
        time.sleep(0.4)
        started = time.monotonic()
        proc.send_signal(signal.SIGSTOP if mode == "paused" else signal.SIGKILL)
        refused_at = poll.wait_for(lambda status: status != ALLOWED, since=started, timeout=SLO_SECONDS + 8)
        time.sleep(1.0)
        later = [s for at, s in poll.log if refused_at is not None and at > refused_at and s == ALLOWED]
        statuses = sorted({s for at, s in poll.log if refused_at is not None and at >= refused_at})
        if mode == "paused":
            proc.send_signal(signal.SIGCONT)
            recovered = poll.wait_for(lambda status: status == ALLOWED, since=time.monotonic(), timeout=15.0)
        else:
            stack.start("core")
            stack.wait_healthy(f"{stack.core}/health")
            recovered = None  # the in-memory store is gone with the process: a new core knows no agents, so refusal is the right answer
    if refused_at is None:
        return Outcome(f"core {mode}", False, "the gateway kept allowing calls")
    detail = f"first refusal {refused_at - started:.2f} s after core stopped; refusals seen: {statuses}; allowed after the first refusal: {len(later)}"
    if mode == "paused":
        detail += f"; back to allowing {'after resume' if recovered is not None else 'NEVER'}"
        return Outcome(f"core {mode}", not later and recovered is not None and refused_at - started <= SLO_SECONDS, detail)
    return Outcome(f"core {mode}", not later and refused_at - started <= SLO_SECONDS, detail)


def upstream_outage(stack: Stack, op: Operator) -> Outcome:
    _, key = op.new_agent("drill-upstream")
    caller = Caller(stack, key)
    warm(caller)
    stack.procs["upstream"].send_signal(signal.SIGKILL)
    time.sleep(0.5)
    results = [caller.call() for _ in range(5)]
    statuses = sorted({s for s, _ in results})
    slowest = max(t for _, t in results)
    health = httpx.get(f"{stack.gateway}/health", timeout=3.0).status_code
    held = ALLOWED not in statuses and slowest < 35.0 and health == 200
    return Outcome("upstream killed", held, f"answers {statuses}, slowest {slowest:.2f} s, gateway /health {health}")


def report(stack: Stack, actions: list[Measure], outcomes: list[Outcome], trials: int, started: str) -> str:
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip() or "unknown"
    lines = [
        "# Revocation and failure drill (local measurement)",
        "",
        f"- Run: {started} UTC; commit `{commit}`; `scripts/revocation_drill.py`; {trials} trials per action.",
        f"- Machine: {platform.platform()}, Python {platform.python_version()}, {os.cpu_count()} CPUs. **Local loopback, in-memory store: not staging, not production.**",
        f"- Promise (CLAUDE.md 4.5): a freeze or revoke takes effect on the next gateway call, at most {SLO_SECONDS:.0f} s. The gateway reuses a passport lookup for at most "
        "its cache TTL (default 2 s, capped at 2.5 s), plus one refresh.",
        "- Polling: one call every ~50 ms per agent (every second for the \"once a second\" rows), so times are accurate to about 0.1 s (1 s for those rows).",
        "",
        "## Time from the operator's 200 OK to the agent's first refused call (seconds)",
        "",
        "| action | trials | p50 | p95 | max | never refused | allowed after first refusal |",
        "|---|---|---|---|---|---|---|",
        *[m.row() for m in actions],
        "",
        "## Failure modes",
        "",
        "| scenario | result | detail |",
        "|---|---|---|",
        *[o.row() for o in outcomes],
        "",
        "## Not covered here",
        "- Expired agent tokens (the shortest lifetime core allows is 60 s; covered by unit tests of the token verifier).",
        "- Several gateway instances (each holds its own cache; the bound is per instance and the same).",
        "- Real network latency, Cloud Run cold starts, Supabase.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--quick", action="store_true", help="skip the failure-mode scenarios (CI)")
    parser.add_argument("--out", type=Path, default=None, help="write the report as Markdown here")
    args = parser.parse_args(argv)

    started = time.strftime("%Y-%m-%d %H:%M", time.gmtime())
    stack = Stack()
    try:
        stack.up()
        op = Operator(stack)
        op.register_server()
        actions = measure_actions(stack, op, args.trials)
        outcomes: list[Outcome] = []
        if not args.quick:
            outcomes.append(core_outage(stack, op, "paused"))
            op = Operator(stack)
            outcomes.append(core_outage(stack, op, "killed"))
            stack.down()
            stack = Stack()
            stack.up()
            op = Operator(stack)
            op.register_server()
            outcomes.append(upstream_outage(stack, op))
    finally:
        stack.down()
    text = report(stack, actions, outcomes, args.trials, started)
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    held = all(m.held for m in actions) and all(o.held for o in outcomes)
    print("RESULT:", "every check held" if held else "A CHECK FAILED")
    return 0 if held else 1


if __name__ == "__main__":
    raise SystemExit(main())
