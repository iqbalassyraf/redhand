"""
`scripts/staging_agent.py` against a gateway that refuses a stale token (H4.1): it exchanges its key again and retries the call ONCE, so a
passport change (an unfreeze, a scope or expiry edit) costs one extra exchange and not a failed run. A second refusal is reported, never looped on,
and the retry never repeats a call the gateway accepted.
"""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("staging_agent_refresh", ROOT / "scripts" / "staging_agent.py")
assert SPEC is not None and SPEC.loader is not None
agent_script = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent_script)

KEY = "rh_agent_local-test-key-0123456789"
STALE = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "Agent access token is out of date. Request a new one."}}


class Stack(BaseHTTPRequestHandler):
    exchanges: ClassVar[int] = 0
    calls: ClassVar[list[str]] = []
    stale_tokens: ClassVar[set[str]] = set()

    def log_message(self, *_: Any) -> None:
        pass

    def _send(self, status: int, body: Any) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        message = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"null")
        if self.path == "/v1/agent-auth/token":
            Stack.exchanges += 1
            return self._send(200, {"access_token": f"token-{Stack.exchanges}", "expires_in": 600})
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        Stack.calls.append(token)
        if token in Stack.stale_tokens:
            return self._send(401, {**STALE, "id": message.get("id")})
        if "id" not in message:
            return self._send(202, {})
        return self._send(200, {"jsonrpc": "2.0", "id": message["id"], "result": {"content": []}})


@pytest.fixture
def stack() -> Any:
    Stack.exchanges, Stack.calls, Stack.stale_tokens = 0, [], set()
    server = HTTPServer(("127.0.0.1", 0), Stack)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def make_agent(url: str) -> Any:
    return agent_script.Agent("agent 1", url, url, "deepwiki", KEY)


def test_a_stale_token_is_replaced_once_and_the_call_is_retried(stack: str) -> None:
    agent = make_agent(stack)
    ok, _ = agent.ensure_token()
    assert ok
    Stack.stale_tokens = {"token-1"}  # the passport changed after this token was issued
    status, body = agent.call_tool("t", {})
    assert status == 200 and "result" in body
    assert Stack.exchanges == 2 and Stack.calls == ["token-1", "token-2"]


def test_a_second_stale_answer_is_reported_not_looped_on(stack: str) -> None:
    agent = make_agent(stack)
    Stack.stale_tokens = {"token-1", "token-2", "token-3"}
    status, body = agent.call_tool("t", {})
    assert status == 401 and "out of date" in body["error"]["message"]
    assert Stack.exchanges == 2 and len(Stack.calls) == 2, "one retry, no more"


def test_other_refusals_are_not_retried(stack: str) -> None:
    agent = make_agent(stack)
    agent.ensure_token()
    # a 401 that is not about staleness (for example an invalid token) must not trigger a second exchange
    original = Stack.do_POST

    def invalid(self: Any) -> None:
        if self.path != "/v1/agent-auth/token":
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            Stack.calls.append("x")
            return self._send(401, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "Invalid or expired agent access token."}})
        return original(self)

    Stack.do_POST = invalid  # type: ignore[method-assign]
    try:
        status, _ = agent.call_tool("t", {})
    finally:
        Stack.do_POST = original  # type: ignore[method-assign]
    assert status == 401 and Stack.exchanges == 1 and Stack.calls == ["x"]


def test_the_script_recognises_the_exact_words_the_gateway_sends() -> None:
    gateway = (ROOT / "agentwall" / "src" / "gateway" / "service.py").read_text(encoding="utf-8")
    assert f'"{agent_script.STALE_TOKEN_TEXT} Request a new one."' in gateway
