#!/usr/bin/env python3
"""
A small stand-in for an AI agent, to test a RedHand stack end to end. Standard library only.

It behaves like a real MCP client: it exchanges its agent key for a short-lived access token,
then talks MCP (initialize, tools/list, tools/call) to a server THROUGH the RedHand gateway.

  run    Checks the passport in action: allowed call works, out-of-scope call is refused,
         unknown server is refused. Prints PASS/FAIL per check.
  watch  Calls the allowed tool in a loop and prints the moment calls stop (after you freeze
         or revoke the agent in the dashboard) and when they resume (after an unfreeze).
         Use --agents 2 (or more) to watch several agents at once, e.g. for "freeze all".

Agent keys are read from the environment (RH_AGENT_KEY, RH_AGENT_KEY_2, ...) or typed at a
hidden prompt. Keys and tokens are never printed.

Defaults match the staging setup in docs/runbooks/staging-agent-test.md.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
DEFAULT_CORE = "https://redhand-core-825574069297.asia-southeast1.run.app"
DEFAULT_GATEWAY = "https://redhand-gateway-825574069297.asia-southeast1.run.app"
USER_AGENT = "RedHand-StagingAgent/1.0"
PRINT_LOCK = threading.Lock()


def now() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def say(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def http_post(url: str, headers: dict[str, str], body: dict[str, Any] | None) -> tuple[int, dict[str, str], Any]:
    """POST JSON; returns (status, lower-cased response headers, parsed JSON or raw text)."""
    data = json.dumps(body).encode() if body is not None else b""
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("Content-Type", "application/json")
    for name, value in headers.items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            status, raw, response_headers = response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        status, raw, response_headers = error.code, error.read(), error.headers
    except (urllib.error.URLError, TimeoutError) as error:
        return 0, {}, f"connection failed: {error}"
    text = raw.decode("utf-8", errors="replace")
    try:
        parsed: Any = json.loads(text) if text else None
    except json.JSONDecodeError:
        parsed = text
    return status, {k.lower(): v for k, v in response_headers.items()}, parsed


class Agent:
    def __init__(self, label: str, core: str, gateway: str, server: str, key: str) -> None:
        self.label, self.core, self.gateway, self.server, self._key = label, core, gateway, server, key
        self._token: str | None = None
        self._token_expires = 0.0
        self._session: str | None = None
        self._next_id = 1

    # -- authentication -------------------------------------------------------------------
    def ensure_token(self) -> tuple[bool, str]:
        """Exchanges the agent key for an access token when needed. Returns (ok, message)."""
        if self._token and time.time() < self._token_expires - 60:
            return True, "token still valid"
        status, _, body = http_post(f"{self.core}/v1/agent-auth/token", {"Authorization": f"Bearer {self._key}"}, None)
        if status == 200 and isinstance(body, dict):
            self._token = str(body["access_token"])
            self._token_expires = time.time() + int(body.get("expires_in", 600))
            return True, f"token issued, valid {int(body.get('expires_in', 600))} s"
        self._token = None
        detail = body.get("detail") if isinstance(body, dict) else body
        return False, f"token refused (HTTP {status}): {detail}"

    # -- MCP ------------------------------------------------------------------------------
    def mcp(self, method: str, params: dict[str, Any] | None = None, server: str | None = None,
            notification: bool = False) -> tuple[int, Any]:
        ok, message = self.ensure_token()
        if not ok:
            return 401, {"error": {"code": -32005, "message": message}}
        message_body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message_body["params"] = params
        if not notification:
            message_body["id"] = self._next_id
            self._next_id += 1
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json, text/event-stream"}
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        if method != "initialize":
            headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
        status, response_headers, body = http_post(f"{self.gateway}/mcp/{server or self.server}", headers, message_body)
        if method == "initialize" and "mcp-session-id" in response_headers:
            self._session = response_headers["mcp-session-id"]
        return status, body

    def initialize(self) -> tuple[int, Any]:
        status, body = self.mcp("initialize", {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "redhand-staging-agent", "version": "1.0"},
        })
        if status == 200:
            self.mcp("notifications/initialized", notification=True)
        return status, body

    def call_tool(self, name: str, arguments: dict[str, Any]) -> tuple[int, Any]:
        return self.mcp("tools/call", {"name": name, "arguments": arguments})


def describe(status: int, body: Any) -> str:
    """One line explaining an outcome."""
    if isinstance(body, dict) and "error" in body:
        error = body["error"]
        return f"refused (HTTP {status}, code {error.get('code')}): {error.get('message')}"
    if status == 200 and isinstance(body, dict) and "result" in body:
        return "allowed (result received)"
    return f"unexpected (HTTP {status}): {str(body)[:160]}"


# -- run mode -----------------------------------------------------------------------------
def run_checks(agent: Agent, args: argparse.Namespace) -> int:
    failures = 0

    def check(name: str, passed: bool, detail: str) -> None:
        nonlocal failures
        say(f"{'PASS' if passed else 'FAIL'}  {name}\n        {detail}")
        failures += 0 if passed else 1

    ok, message = agent.ensure_token()
    check("agent key is exchanged for an access token", ok, message)
    if not ok:
        return 1

    status, body = agent.initialize()
    check("MCP initialize through the gateway", status == 200 and isinstance(body, dict) and "result" in body, describe(status, body))

    status, body = agent.mcp("tools/list")
    names = [t.get("name") for t in body.get("result", {}).get("tools", [])] if isinstance(body, dict) else []
    check("tools/list shows only what the passport allows", status == 200 and args.denied_tool not in names,
          f"visible tools: {names or 'none'}")

    status, body = agent.call_tool(args.ok_tool, json.loads(args.ok_args))
    check(f"in-scope call '{args.ok_tool}' succeeds", status == 200 and isinstance(body, dict) and "result" in body, describe(status, body))

    status, body = agent.call_tool(args.denied_tool, json.loads(args.denied_args))
    code = body.get("error", {}).get("code") if isinstance(body, dict) else None
    check(f"out-of-scope call '{args.denied_tool}' is refused", code == -32000, describe(status, body))

    status, body = agent.mcp("tools/list", server="no-such-server-xyz")
    check("unknown server is refused", status in (404, 403) or (isinstance(body, dict) and "error" in body), describe(status, body))

    say("\nALL CHECKS PASSED" if failures == 0 else f"\n{failures} CHECK(S) FAILED")
    return 0 if failures == 0 else 1


# -- watch mode ---------------------------------------------------------------------------
def watch_agent(agent: Agent, args: argparse.Namespace, stop: threading.Event) -> None:
    last_ok: str | None = None
    state = "unknown"
    status, body = agent.initialize()
    if status != 200:
        say(f"[{agent.label}] could not start: {describe(status, body)}")
        return
    say(f"[{agent.label}] {now()} started; calling '{args.ok_tool}' every {args.interval}s")
    while not stop.is_set():
        status, body = agent.call_tool(args.ok_tool, json.loads(args.ok_args))
        allowed = status == 200 and isinstance(body, dict) and "result" in body
        if allowed:
            if state == "denied":
                say(f"[{agent.label}] {now()} >>> RESUMED (calls are allowed again)")
            elif state == "unknown":
                say(f"[{agent.label}] {now()} calls are allowed")
            state, last_ok = "allowed", now()
        else:
            if state != "denied":
                say(f"[{agent.label}] {now()} >>> STOPPED  last success {last_ok or 'never'}  |  {describe(status, body)}")
            state = "denied"
        stop.wait(args.interval)


def watch(agents: list[Agent], args: argparse.Namespace) -> int:
    stop = threading.Event()
    threads = [threading.Thread(target=watch_agent, args=(a, args, stop), daemon=True) for a in agents]
    for thread in threads:
        thread.start()
    say("Watching. Freeze or revoke in the dashboard and note the time. Press Ctrl+C to stop.")
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()
        say("\nstopped.")
    return 0


# -- main ---------------------------------------------------------------------------------
def read_keys(count: int) -> list[str]:
    keys = []
    for index in range(1, count + 1):
        env_name = "RH_AGENT_KEY" if index == 1 else f"RH_AGENT_KEY_{index}"
        key = os.environ.get(env_name) or getpass.getpass(f"Paste agent key {index} (input is hidden): ").strip()
        if not key.startswith("rh_agent_"):
            sys.exit("That does not look like an agent key (it should start with rh_agent_).")
        keys.append(key)
    return keys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["run", "watch"])
    parser.add_argument("--core", default=os.environ.get("RH_CORE_URL", DEFAULT_CORE))
    parser.add_argument("--gateway", default=os.environ.get("RH_GATEWAY_URL", DEFAULT_GATEWAY))
    parser.add_argument("--server", default="deepwiki", help="MCP server slug registered in the dashboard")
    parser.add_argument("--ok-tool", default="read_wiki_structure")
    parser.add_argument("--ok-args", default='{"repoName": "facebook/react"}')
    parser.add_argument("--denied-tool", default="ask_question")
    parser.add_argument("--denied-args", default='{"repoName": "facebook/react", "question": "What is React?"}')
    parser.add_argument("--agents", type=int, default=1, help="watch mode: how many agents to watch")
    parser.add_argument("--interval", type=float, default=1.0, help="watch mode: seconds between calls")
    args = parser.parse_args()
    for url_name in ("core", "gateway"):
        setattr(args, url_name, getattr(args, url_name).rstrip("/"))

    count = args.agents if args.mode == "watch" else 1
    agents = [Agent(f"agent {i + 1}", args.core, args.gateway, args.server, key) for i, key in enumerate(read_keys(count))]
    say(f"core: {args.core}\ngateway: {args.gateway}\nserver: {args.server}\n")
    return run_checks(agents[0], args) if args.mode == "run" else watch(agents, args)


if __name__ == "__main__":
    sys.exit(main())
