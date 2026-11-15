"""
`scripts/staging_agent.py repeat` (the night brief's tool for the loop and destination checks): against a local stand-in for core and the gateway, it
sends the same call N times, prints one line per call and a summary, finds the first refusal, can vary an argument, and never prints the agent key, the
token or the arguments it sent.
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
SPEC = importlib.util.spec_from_file_location(
    "staging_agent", ROOT / "scripts" / "staging_agent.py"
)
assert SPEC is not None and SPEC.loader is not None
agent_script = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent_script)

KEY = "rh_agent_local-test-key-0123456789"
TOKEN = "local-access-token-abcdef0123456789"
SECRET_ARGUMENT = "zq-secret-argument-5719"


class FakeStack(BaseHTTPRequestHandler):
    refuse_from = 4  # the 4th identical call and every one after it is refused
    received: ClassVar[list[dict[str, Any]]] = []

    def log_message(self, *_: Any) -> None:
        pass

    def _send(self, status: int, body: Any) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        message = json.loads(self.rfile.read(length) or b"null")
        if self.path == "/v1/agent-auth/token":
            return self._send(200, {"access_token": TOKEN, "expires_in": 600})
        if message.get("method") == "tools/call":
            FakeStack.received.append(message["params"]["arguments"])
            seen = len([a for a in FakeStack.received if a == message["params"]["arguments"]])
            if seen >= FakeStack.refuse_from:
                return self._send(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {
                            "code": -32000,
                            "message": "PolicyViolation: this exact call was repeated too often",
                        },
                    },
                )
        if "id" not in message:
            return self._send(202, {})
        return self._send(200, {"jsonrpc": "2.0", "id": message["id"], "result": {"content": []}})


@pytest.fixture
def stack() -> Any:
    FakeStack.received = []
    FakeStack.refuse_from = 4
    server = HTTPServer(("127.0.0.1", 0), FakeStack)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def run(
    url: str, extra: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> tuple[int, str]:
    monkeypatch.setenv("RH_AGENT_KEY", KEY)
    code = agent_script.main(["repeat", "--core", url, "--gateway", url, "--delay", "0", *extra])
    return code, capsys.readouterr().out


def test_repeat_sends_the_same_call_and_reports_the_first_refusal(
    stack: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = run(
        stack, ["--times", "6", "--tool", "t", "--args", json.dumps({"id": 1})], monkeypatch, capsys
    )
    assert code == 0
    assert "summary: 6 calls" in out and "3 x allowed" in out and "first refusal at call: 4" in out
    assert (
        "refused (HTTP 200, code -32000): PolicyViolation: this exact call was repeated too often"
        in out
    )
    assert len(FakeStack.received) == 6 and all(a == {"id": 1} for a in FakeStack.received)


def test_repeat_with_vary_sends_a_different_call_each_time(
    stack: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = run(
        stack,
        ["--times", "8", "--args", json.dumps({"id": 1}), "--vary", "nonce"],
        monkeypatch,
        capsys,
    )
    assert code == 0 and "8 x allowed" in out and "first refusal at call: none" in out
    assert len({a["nonce"] for a in FakeStack.received}) == 8


def test_repeat_never_prints_the_key_the_token_or_the_arguments(
    stack: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, out = run(
        stack,
        [
            "--times",
            "5",
            "--args",
            json.dumps({"note": SECRET_ARGUMENT, "url": "https://evil.example/x"}),
        ],
        monkeypatch,
        capsys,
    )
    for secret in (KEY, TOKEN, SECRET_ARGUMENT, "evil.example"):
        assert secret not in out


def test_repeat_reports_a_start_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = run("http://127.0.0.1:9", ["--times", "2"], monkeypatch, capsys)
    assert code == 1 and "could not start" in out
