"""
The model proxy prototype (Phase 4.5 B5, docs/adr/0025-model-proxy-prototype.md): an agent points its Anthropic SDK at the gateway with its RedHand token;
the gateway checks the passport and the model, forwards to the provider with the deployment's own key, and records the usage the provider reports.

Everything here talks to a fake provider (httpx.MockTransport): no network, no real key. The proxy must fail closed (no key, no passport lookup, a passport
that is not active, a model the passport does not cover, a malformed or oversized request: all refused before anything is sent), never forward the agent's
token or leak the provider key, bound request, response and stream sizes, pass a stream through byte for byte, and record usage exactly once.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr

from agentwall.src.gateway.context import AgentUnknownError, ContextUnavailableError
from agentwall.src.gateway.identity import AgentAuthError, AgentIdentity, KeyUnavailableError
from agentwall.src.gateway.model_proxy import ModelProxy, ModelProxyConfig, ModelUsage, MemoryUsageSink, mount_model_proxy

PROVIDER_KEY = "sk-" + "ant-" + "api03-" + "FAKE" * 10  # built from pieces so the repository secret scan does not see a key on this line
AGENT_TOKEN = "agent-token-for-tests"
ORG = uuid4()
AGENT = uuid4()
SONNET = "claude-sonnet-5-5"


class FakeVerifier:
    def __init__(self) -> None:
        self.error: Exception | None = None

    async def verify(self, token: str) -> AgentIdentity:
        if self.error is not None:
            raise self.error
        if token != AGENT_TOKEN:
            raise AgentAuthError("bad token")
        return AgentIdentity(agent_id=AGENT, organization_id=ORG, passport_version=1, token_id="jti-1", expires_at=4_000_000_000)


class FakeContexts:
    def __init__(self) -> None:
        self.status = "active"
        self.models = {SONNET}
        self.error: Exception | None = None
        self.calls: list[tuple[Any, Any, str]] = []
        self.version = 1
        self.model_spend: Any = None

    async def get(self, agent_id: Any, organization_id: Any, server: str) -> Any:
        self.calls.append((agent_id, organization_id, server))
        if self.error is not None:
            raise self.error
        models = self.models
        return SimpleNamespace(status=self.status, passport_version=self.version, covers_tool=lambda tool: "*" in models or tool in models, model_spend=self.model_spend)


class Provider:
    """A fake Anthropic: records what it was sent and answers as scripted."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.body: dict[str, Any] = {"id": "msg_1", "type": "message", "model": SONNET, "content": [{"type": "text", "text": "hi"}],
                                     "usage": {"input_tokens": 12, "output_tokens": 7}}
        self.stream_chunks: list[bytes] | None = None
        self.stream_error_after: int | None = None
        self.raw: bytes | None = None
        self.headers: dict[str, str] = {"request-id": "req_1", "set-cookie": "a=b", "x-internal": "no"}

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.stream_chunks is not None:
            async def gen() -> Any:
                for i, chunk in enumerate(self.stream_chunks or []):
                    if self.stream_error_after is not None and i >= self.stream_error_after:
                        raise httpx.ReadError("provider connection dropped")
                    yield chunk
            return httpx.Response(self.status, headers={"content-type": "text/event-stream", **self.headers}, stream=AsyncGen(gen()))
        content = self.raw if self.raw is not None else json.dumps(self.body).encode()
        return httpx.Response(self.status, headers={"content-type": "application/json", **self.headers}, stream=AsyncGen(self._one(content)))

    @staticmethod
    async def _one(content: bytes) -> Any:
        yield content


class AsyncGen(httpx.AsyncByteStream):
    """A response body that is only ever read as a stream, like a real connection (httpx marks `content=` bodies as already read)."""

    def __init__(self, gen: Any) -> None:
        self._gen = gen

    async def __aiter__(self) -> Any:
        async for chunk in self._gen:
            yield chunk


def sse(events: list[tuple[str, dict[str, Any]]]) -> list[bytes]:
    return [f"event: {name}\ndata: {json.dumps(data)}\n\n".encode() for name, data in events]


STREAM = sse([
    ("message_start", {"type": "message_start", "message": {"id": "msg_1", "usage": {"input_tokens": 25, "output_tokens": 1}}}),
    ("content_block_delta", {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Hel"}}),
    ("content_block_delta", {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "lo"}}),
    ("message_delta", {"type": "message_delta", "usage": {"output_tokens": 42}}),
    ("message_stop", {"type": "message_stop"}),
])


class World:
    def __init__(self, **config: Any) -> None:
        self.provider = Provider()
        self.verifier = FakeVerifier()
        self.contexts = FakeContexts()
        self.sink = MemoryUsageSink()
        settings: dict[str, Any] = {"enabled": True, "provider_url": "https://provider.test", "provider_key": SecretStr(PROVIDER_KEY)}
        settings.update(config)
        self.config = ModelProxyConfig(**settings)
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.provider.handler), base_url="https://provider.test")
        self.proxy = ModelProxy(verifier=self.verifier, contexts=self.contexts, client=self.client, config=self.config, sink=self.sink)
        app = FastAPI()
        mount_model_proxy(app, self.proxy)
        self.http = TestClient(app)

    def post(self, body: Any = None, token: str | None = AGENT_TOKEN, headers: dict[str, str] | None = None, raw: bytes | None = None) -> httpx.Response:
        payload = body if body is not None else {"model": SONNET, "max_tokens": 100, "messages": [{"role": "user", "content": "hello"}]}
        h = dict(headers or {})
        if token is not None:
            h.setdefault("Authorization", f"Bearer {token}")
        return self.http.post("/v1/model/anthropic/v1/messages", content=raw if raw is not None else json.dumps(payload), headers={"content-type": "application/json", **h})


@pytest.fixture
def w() -> World:
    return World()


# --- the allowed path ------------------------------------------------------------------------------------------------------------------

def test_an_allowed_call_is_forwarded_with_the_provider_key_and_never_the_agent_token(w: World) -> None:
    response = w.post(headers={"anthropic-version": "2023-06-01", "x-api-key": "should-not-be-forwarded", "cookie": "s=1"})
    assert response.status_code == 200 and response.json()["content"][0]["text"] == "hi"
    sent = w.provider.requests[0]
    assert str(sent.url) == "https://provider.test/v1/messages"
    assert sent.headers["x-api-key"] == PROVIDER_KEY
    assert sent.headers["anthropic-version"] == "2023-06-01"
    assert "authorization" not in sent.headers and "cookie" not in sent.headers
    assert AGENT_TOKEN not in json.dumps(dict(sent.headers)) and "should-not-be-forwarded" not in json.dumps(dict(sent.headers))
    assert json.loads(sent.content)["model"] == SONNET


def test_the_body_is_forwarded_byte_for_byte(w: World) -> None:
    raw = b'{ "model":"claude-sonnet-5-5","max_tokens":10,  "messages":[{"role":"user","content":"x"}] }'
    assert w.post(raw=raw).status_code == 200
    assert w.provider.requests[0].content == raw


def test_the_agent_may_send_its_token_as_the_sdk_api_key(w: World) -> None:
    assert w.post(token=None, headers={"x-api-key": AGENT_TOKEN}).status_code == 200


def test_response_headers_are_an_allowlist(w: World) -> None:
    response = w.post()
    assert response.headers["request-id"] == "req_1"
    assert "set-cookie" not in response.headers and "x-internal" not in response.headers
    assert PROVIDER_KEY not in response.text and PROVIDER_KEY not in json.dumps(dict(response.headers))


def test_the_passport_is_looked_up_for_the_model_server_name(w: World) -> None:
    w.post()
    assert w.contexts.calls == [(AGENT, ORG, "model")]


def test_usage_is_recorded_once_from_what_the_provider_reported(w: World) -> None:
    w.post()
    assert w.sink.items == [ModelUsage(agent_id=AGENT, organization_id=ORG, model=SONNET, input_tokens=12, output_tokens=7, stream=False, outcome="ok")]


def test_a_response_without_usage_is_recorded_as_not_reported_never_invented(w: World) -> None:
    w.provider.body = {"id": "m", "content": []}
    w.post()
    assert (w.sink.items[0].input_tokens, w.sink.items[0].output_tokens, w.sink.items[0].outcome) == (0, 0, "usage_not_reported")


# --- refusals: nothing is sent upstream ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("token", [None, "wrong", ""])
def test_a_missing_or_bad_agent_token_is_refused_with_401(w: World, token: str | None) -> None:
    assert w.post(token=token, headers={"Authorization": f"Bearer {token}"} if token == "" else None).status_code == 401
    assert w.provider.requests == [] and w.contexts.calls == []


def test_a_token_check_that_cannot_run_is_refused_with_503(w: World) -> None:
    w.verifier.error = KeyUnavailableError("no keys")
    assert w.post().status_code == 503 and w.provider.requests == []


@pytest.mark.parametrize("status", ["frozen", "revoked", "expired"])
def test_a_passport_that_is_not_active_is_refused_with_403(w: World, status: str) -> None:
    w.contexts.status = status
    response = w.post()
    assert response.status_code == 403 and status in response.json()["error"]["message"]
    assert w.provider.requests == []


def test_a_token_from_an_older_passport_version_is_refused(w: World) -> None:
    w.contexts.version = 2
    assert w.post().status_code == 401 and w.provider.requests == []


def test_a_passport_lookup_that_fails_denies(w: World) -> None:
    w.contexts.error = ContextUnavailableError("core down")
    assert w.post().status_code == 503 and w.provider.requests == []
    w.contexts.error = AgentUnknownError("who")
    assert w.post().status_code == 401 and w.provider.requests == []


def test_a_model_the_passport_does_not_cover_is_refused_with_403(w: World) -> None:
    w.contexts.models = {"claude-haiku-5-5"}
    response = w.post()
    assert response.status_code == 403 and response.json()["error"]["type"] == "permission_error"
    assert w.provider.requests == []


def test_a_wildcard_scope_covers_any_listed_model_but_the_deployment_list_still_applies() -> None:
    w = World(allowed_models=frozenset({SONNET}))
    w.contexts.models = {"*"}
    assert w.post().status_code == 200
    assert w.post({"model": "claude-opus-5-5", "max_tokens": 5, "messages": []}).status_code == 403
    assert len(w.provider.requests) == 1


def test_a_deployment_with_no_provider_key_refuses_everything() -> None:
    w = World(provider_key=None)
    assert w.post().status_code == 503 and w.provider.requests == [] and w.contexts.calls == []


def test_a_disabled_proxy_has_no_route() -> None:
    w = World(enabled=False)
    assert w.post().status_code == 404 and w.provider.requests == []


@pytest.mark.parametrize(
    "body",
    [[], "text", {"messages": []}, {"model": 5, "max_tokens": 1}, {"model": "", "max_tokens": 1}, {"model": "bad model!", "max_tokens": 1},
     {"model": "x" * 200, "max_tokens": 1}, {"model": SONNET}, {"model": SONNET, "max_tokens": "10"}, {"model": SONNET, "max_tokens": 0},
     {"model": SONNET, "max_tokens": True}, {"model": SONNET, "max_tokens": 10, "stream": "yes"}],
    ids=["array", "string", "no model", "int model", "empty model", "bad chars", "long model", "no max_tokens", "string max_tokens", "zero max_tokens",
         "bool max_tokens", "stream not bool"],
)
def test_a_malformed_request_is_refused_with_400_before_anything_is_sent(w: World, body: Any) -> None:
    assert w.post(body).status_code == 400 and w.provider.requests == []


def test_not_json_is_refused_with_400(w: World) -> None:
    assert w.post(raw=b"{not json").status_code == 400
    assert w.post(raw=b'{"model":"m","max_tokens":NaN}').status_code == 400
    assert w.provider.requests == []


def test_max_tokens_above_the_cap_is_refused(w: World) -> None:
    capped = World(max_tokens_cap=1000)
    assert capped.post({"model": SONNET, "max_tokens": 1001, "messages": []}).status_code == 400
    assert capped.post({"model": SONNET, "max_tokens": 1000, "messages": []}).status_code == 200


def test_an_oversized_request_is_refused_with_413_without_reading_it_all() -> None:
    w = World(max_request_bytes=2048)
    big = {"model": SONNET, "max_tokens": 5, "messages": [{"role": "user", "content": "x" * 5000}]}
    assert w.post(big).status_code == 413 and w.provider.requests == []


# --- the provider side -----------------------------------------------------------------------------------------------------------------

def test_a_provider_error_is_passed_on_but_never_counts_as_usage(w: World) -> None:
    w.provider.status = 429
    w.provider.body = {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}
    w.provider.headers["retry-after"] = "7"
    response = w.post()
    assert response.status_code == 429 and response.json()["error"]["type"] == "rate_limit_error" and response.headers["retry-after"] == "7"
    assert w.sink.items[0].outcome == "provider_error" and (w.sink.items[0].input_tokens, w.sink.items[0].output_tokens) == (0, 0)


@pytest.mark.parametrize("status", [401, 403])
def test_a_provider_that_rejects_the_gateways_key_is_a_502_not_the_agents_problem(w: World, status: int) -> None:
    w.provider.status = status
    w.provider.body = {"type": "error", "error": {"type": "authentication_error", "message": f"invalid x-api-key {PROVIDER_KEY}"}}
    response = w.post()
    assert response.status_code == 502 and PROVIDER_KEY not in response.text


def test_a_provider_that_cannot_be_reached_is_a_502(w: World) -> None:
    async def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    w.client = httpx.AsyncClient(transport=httpx.MockTransport(boom), base_url="https://provider.test")
    w.proxy.client = w.client
    response = w.post()
    assert response.status_code == 502 and "provider" in response.json()["error"]["message"].lower()
    assert w.sink.items[0].outcome == "provider_unreachable"


def test_a_response_bigger_than_the_cap_is_cut_off_with_a_502() -> None:
    w = World(max_response_bytes=1024)
    w.provider.raw = b'{"content":"' + b"x" * 5000 + b'"}'
    assert w.post().status_code == 502


def test_a_provider_that_answers_with_something_that_is_not_json_is_a_502(w: World) -> None:
    w.provider.raw = b"<html>gateway timeout</html>"
    assert w.post().status_code == 502


# --- streaming -------------------------------------------------------------------------------------------------------------------------

def stream_body() -> dict[str, Any]:
    return {"model": SONNET, "max_tokens": 50, "stream": True, "messages": [{"role": "user", "content": "hi"}]}


def test_a_stream_is_passed_through_byte_for_byte_and_usage_is_read_from_its_events(w: World) -> None:
    w.provider.stream_chunks = STREAM
    response = w.post(stream_body())
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/event-stream")
    assert response.content == b"".join(STREAM)
    assert w.sink.items == [ModelUsage(agent_id=AGENT, organization_id=ORG, model=SONNET, input_tokens=25, output_tokens=42, stream=True, outcome="ok")]


def test_events_split_across_chunks_are_still_counted() -> None:
    w = World()
    whole = b"".join(STREAM)
    w.provider.stream_chunks = [whole[i:i + 7] for i in range(0, len(whole), 7)]  # cut anywhere, even inside a line
    response = w.post(stream_body())
    assert response.content == whole
    assert (w.sink.items[0].input_tokens, w.sink.items[0].output_tokens) == (25, 42)


def test_a_stream_that_breaks_midway_is_recorded_as_interrupted_with_what_was_seen() -> None:
    w = World()
    w.provider.stream_chunks = STREAM
    w.provider.stream_error_after = 2
    with pytest.raises(Exception):
        w.post(stream_body())
    assert len(w.sink.items) == 1 and w.sink.items[0].outcome == "stream_interrupted" and w.sink.items[0].input_tokens == 25


def test_a_stream_bigger_than_the_cap_is_stopped() -> None:
    w = World(max_stream_bytes=300)
    w.provider.stream_chunks = [b"data: " + b"x" * 100 + b"\n\n"] * 20
    with pytest.raises(Exception):
        w.post(stream_body())
    assert w.sink.items[0].outcome == "stream_too_large"


def test_an_event_line_that_is_too_long_does_not_stop_the_stream_or_grow_memory() -> None:
    w = World()
    w.provider.stream_chunks = [b"data: " + b"x" * 200_000, b"\n\n"] + STREAM
    response = w.post(stream_body())
    assert response.status_code == 200 and response.content.endswith(b"".join(STREAM))
    assert w.sink.items[0].outcome in ("ok", "usage_not_reported")


def test_a_frozen_agent_gets_no_stream() -> None:
    w = World()
    w.provider.stream_chunks = STREAM
    w.contexts.status = "frozen"
    assert w.post(stream_body()).status_code == 403 and w.provider.requests == []


def test_usage_is_recorded_exactly_once_per_call(w: World) -> None:
    w.provider.stream_chunks = STREAM
    w.post(stream_body())
    w.post(stream_body())
    assert len(w.sink.items) == 2


# --- hygiene ---------------------------------------------------------------------------------------------------------------------------

def test_the_provider_key_is_never_in_a_log_line_or_the_sink(w: World, capsys: pytest.CaptureFixture[str]) -> None:
    w.provider.status = 500
    w.provider.body = {"error": f"boom {PROVIDER_KEY}"}
    w.post()
    out = capsys.readouterr()
    assert PROVIDER_KEY not in out.out + out.err and PROVIDER_KEY not in repr(w.sink.items) and AGENT_TOKEN not in out.out + out.err


def test_stats_count_outcomes_and_tokens_for_prometheus(w: World) -> None:
    w.post()
    w.post(token="nope")
    text = w.proxy.render_prometheus()
    assert 'agentwall_model_proxy_requests_total{outcome="ok"} 1' in text and 'agentwall_model_proxy_requests_total{outcome="unauthorized"} 1' in text
    assert "agentwall_model_proxy_tokens_total" in text and PROVIDER_KEY not in text


def test_a_concurrent_burst_records_each_call_once() -> None:
    w = World()

    async def burst() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=w.http.app), base_url="http://gw") as client:
            await asyncio.gather(*[client.post("/v1/model/anthropic/v1/messages", json={"model": SONNET, "max_tokens": 5, "messages": []},
                                               headers={"Authorization": f"Bearer {AGENT_TOKEN}"}) for _ in range(25)])

    asyncio.run(burst())
    assert len(w.sink.items) == 25


def test_the_route_is_mounted_only_when_enabled() -> None:
    app = FastAPI()
    mount_model_proxy(app, World(enabled=False).proxy)
    assert not [r for r in app.routes if getattr(r, "path", "").startswith("/v1/model")]
    assert isinstance(Request, type)


def test_the_stream_parser_never_holds_more_than_one_capped_line() -> None:
    from agentwall.src.gateway.model_proxy import MAX_EVENT_LINE, StreamUsageParser

    parser = StreamUsageParser()
    for _ in range(40):
        parser.feed(b"data: " + b"x" * 100_000)  # 4 MB with no line break
        assert len(parser._line) <= MAX_EVENT_LINE  # noqa: SLF001
    parser.feed(b"\n")
    parser.feed(STREAM[0])
    assert parser.input_tokens == 25, "after the over-long line is dropped the next events are read again"


# --- the production guard (B5a): provider-key custody does not exist yet, so the proxy cannot be switched on where customers are ------------------

@pytest.mark.parametrize("environment", ["development", "dev", "test", "local", "staging", "Staging"])
def test_the_proxy_may_be_enabled_in_local_and_staging_environments(environment: str) -> None:
    from agentwall.config.settings import Settings

    assert Settings(ENVIRONMENT=environment, MODEL_PROXY_ENABLED=True).MODEL_PROXY_ENABLED is True


@pytest.mark.parametrize("environment", ["production", "prod", "Production", "prd", "live", ""])
def test_the_proxy_refuses_to_start_anywhere_else_including_typos(environment: str) -> None:
    from agentwall.config.settings import Settings

    with pytest.raises(ValueError, match="MODEL_PROXY_ENABLED"):
        Settings(ENVIRONMENT=environment, MODEL_PROXY_ENABLED=True)


def test_a_production_gateway_without_the_proxy_is_unaffected() -> None:
    from agentwall.config.settings import Settings

    assert Settings(ENVIRONMENT="production").MODEL_PROXY_ENABLED is False


# --- B5c: refusing over the daily dollar limit (measured spend, ADR 0025) -------------------------------------------------------------

def spend(limit: int = 5_000_000, measured: int = 0, known: bool = True, priced: tuple[str, ...] = (SONNET, "claude-haiku-5-5")) -> SimpleNamespace:
    return SimpleNamespace(limit_micro_usd=limit, measured_micro_usd=measured, spend_known=known, priced_models=frozenset(priced))


def test_a_call_under_the_limit_is_forwarded(w: World) -> None:
    w.contexts.model_spend = spend(measured=4_999_999)
    assert w.post().status_code == 200 and len(w.provider.requests) == 1


@pytest.mark.parametrize("measured", [5_000_000, 5_000_001, 10**12])
def test_a_call_at_or_over_the_limit_is_refused_before_the_provider(w: World, measured: int) -> None:
    w.contexts.model_spend = spend(limit=5_000_000, measured=measured)
    response = w.post()
    assert response.status_code == 429 and response.json()["error"]["type"] == "rate_limit_error"
    assert "daily model spend limit" in response.json()["error"]["message"]
    assert w.provider.requests == [] and w.sink.items == []
    assert 'outcome="spend_limit"' in w.proxy.render_prometheus()


def test_the_refusal_leaks_no_numbers_and_no_key(w: World) -> None:
    w.contexts.model_spend = spend(limit=123_456, measured=999_999)
    text = w.post().text
    assert "123456" not in text and "999999" not in text and PROVIDER_KEY not in text and AGENT_TOKEN not in text


def test_a_limit_of_zero_refuses_everything_the_restrictive_reading(w: World) -> None:
    w.contexts.model_spend = spend(limit=0, measured=0)
    assert w.post().status_code == 429 and w.provider.requests == []


def test_no_limit_means_no_check(w: World) -> None:
    w.contexts.model_spend = None
    assert w.post().status_code == 200


def test_unknown_spend_with_a_limit_set_is_refused_not_assumed_zero(w: World) -> None:
    w.contexts.model_spend = spend(measured=0, known=False)
    response = w.post()
    assert response.status_code == 403 and "cannot be priced" in response.json()["error"]["message"]
    assert w.provider.requests == [] and 'outcome="spend_unpriced"' in w.proxy.render_prometheus()


def test_a_model_the_price_table_does_not_know_is_refused_when_a_limit_is_set(w: World) -> None:
    w.contexts.models = {"*"}
    w.contexts.model_spend = spend(priced=(SONNET,))
    assert w.post(body={"model": "mystery-model", "max_tokens": 10, "messages": [{"role": "user", "content": "x"}]}).status_code == 403
    assert w.provider.requests == []


@pytest.mark.parametrize("model", [f"{SONNET}-20261101", SONNET.upper()])
def test_a_dated_or_differently_cased_id_is_priced_by_the_same_rule_as_core(w: World, model: str) -> None:
    w.contexts.models = {"*"}
    w.contexts.model_spend = spend(measured=1)
    assert w.post(body={"model": model, "max_tokens": 10, "messages": [{"role": "user", "content": "x"}]}).status_code == 200


def test_the_limit_is_checked_after_the_passport_and_the_model_scope(w: World) -> None:
    w.contexts.model_spend = spend(measured=10**12)
    w.contexts.status = "frozen"
    assert w.post().status_code == 403 and "frozen" in w.post().json()["error"]["message"]
    w.contexts.status = "active"
    w.contexts.models = {"claude-haiku-5-5"}
    assert w.post().status_code == 403 and "may not use the model" in w.post().json()["error"]["message"]


def test_a_streaming_call_over_the_limit_is_refused_before_any_byte_is_streamed(w: World) -> None:
    w.contexts.model_spend = spend(measured=5_000_000)
    body = {"model": SONNET, "max_tokens": 10, "stream": True, "messages": [{"role": "user", "content": "x"}]}
    response = w.post(body=body)
    assert response.status_code == 429 and response.headers["content-type"].startswith("application/json") and w.provider.requests == []
