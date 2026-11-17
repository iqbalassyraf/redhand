"""
AgentWall - model proxy PROTOTYPE (Phase 4.5 B5, docs/adr/0025-model-proxy-prototype.md). Off unless AGENTWALL_MODEL_PROXY_ENABLED is set.

An agent points its Anthropic SDK at `<gateway>/v1/model/anthropic` and uses its RedHand agent token as the credential. For each call the gateway:
  1. refuses unless the deployment has a provider key (fail closed, before anything else);
  2. verifies the agent token (the same verifier as the tool route);
  3. validates the request shape and size (a JSON object with a model name, an integer max_tokens inside a cap, an optional boolean stream);
  4. looks the passport up through the same short cache as tool calls: it must be active, the token not older than the passport, and one of its scopes must
     cover the model (server "model", tool = the model id, or "*"), so approved models are enforced per agent with the existing scope editor;
  5. forwards the original bytes to the provider with the deployment's key (never the agent's token or cookies) and passes the answer back through a header
     allowlist, a response-size cap, and for streams a byte cap and an idle timeout, byte for byte;
  6. records the usage the PROVIDER reported (not the agent's SDK), exactly once per call, to a usage sink.

What this prototype does not do (and the ADR says so): per-tenant provider keys, reporting usage on to core's spend roll-up, per-token inspection or redaction
of prompts and completions, other providers. Nothing here reads or stores prompt or completion text.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections import Counter
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import SecretStr

from .context import AgentUnknownError, ContextUnavailableError
from .identity import AgentAuthError, AgentIdentity, KeyUnavailableError

logger = structlog.get_logger(__name__)

MODEL_SERVER_NAME = "model"  # the scope server name and the passport-lookup key for model calls
ROUTE = "/v1/model/anthropic/v1/messages"
MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
MAX_EVENT_LINE = 64 * 1024  # one SSE line longer than this is passed through but not parsed
PASS_REQUEST_HEADERS = ("anthropic-version", "anthropic-beta", "accept")
PASS_RESPONSE_HEADERS = ("content-type", "request-id", "retry-after", "cache-control")
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"


@dataclass(frozen=True)
class ModelProxyConfig:
    enabled: bool = False
    provider_url: str = "https://api.anthropic.com"
    provider_key: SecretStr | None = None
    allowed_models: frozenset[str] = frozenset()  # an extra deployment-wide limit; empty means the passport scopes alone decide
    max_request_bytes: int = 1024 * 1024
    max_tokens_cap: int = 32_000
    max_response_bytes: int = 8 * 1024 * 1024
    max_stream_bytes: int = 32 * 1024 * 1024
    connect_timeout: float = 5.0
    total_timeout: float = 120.0
    stream_idle_timeout: float = 60.0


@dataclass(frozen=True)
class ModelUsage:
    """What one call used, as the provider reported it. Zero tokens with outcome `usage_not_reported` means not reported, never "free"."""

    agent_id: UUID
    organization_id: UUID
    model: str
    input_tokens: int
    output_tokens: int
    stream: bool
    outcome: str


class UsageSink(Protocol):
    def record(self, usage: ModelUsage) -> None: ...


@dataclass
class MemoryUsageSink:
    """Keeps the most recent usage records in memory. The prototype's stand-in for reporting to core's spend roll-up (not built: see the ADR)."""

    limit: int = 10_000
    items: list[ModelUsage] = field(default_factory=list)

    def record(self, usage: ModelUsage) -> None:
        self.items.append(usage)
        if len(self.items) > self.limit:
            del self.items[: len(self.items) - self.limit]


_DATE_STAMP = re.compile(r"^(?P<base>.+)-\d{8}$")


def _price_key(model: str) -> str:
    """The model id as core's price table keys it: lower case, a trailing -YYYYMMDD stamp ignored (the same rule as spend/prices.py price_for; a test in core pins them together)."""
    key = model.strip().lower()
    dated = _DATE_STAMP.match(key)
    return dated.group("base") if dated else key


def _error(status: int, kind: str, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    headers = dict(headers or {})
    if status == 401:
        headers["WWW-Authenticate"] = 'Bearer realm="redhand-gateway"'
    return JSONResponse(status_code=status, content={"type": "error", "error": {"type": kind, "message": message}}, headers=headers)


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000_000 else None


def _usage_from(obj: Any) -> tuple[int | None, int | None]:
    usage = obj.get("usage") if isinstance(obj, dict) else None
    if not isinstance(usage, dict):
        return None, None
    return _count(usage.get("input_tokens")), _count(usage.get("output_tokens"))


class StreamUsageParser:
    """Reads token counts out of an Anthropic server-sent stream without holding it: only the current partial line is kept, and a line over
    MAX_EVENT_LINE is skipped. Never raises on what the provider sends."""

    def __init__(self) -> None:
        self.input_tokens: int | None = None
        self.output_tokens: int | None = None
        self._line = bytearray()
        self._skipping = False

    def feed(self, chunk: bytes) -> None:
        for line in self._split(chunk):
            self._handle(line)

    def _split(self, chunk: bytes) -> list[bytes]:
        done: list[bytes] = []
        start = 0
        while True:
            end = chunk.find(b"\n", start)
            if end == -1:
                self._append(chunk[start:])
                return done
            self._append(chunk[start:end])
            done.append(b"" if self._skipping else bytes(self._line))
            self._line.clear()
            self._skipping = False
            start = end + 1

    def _append(self, part: bytes) -> None:
        if self._skipping:
            return
        if len(self._line) + len(part) > MAX_EVENT_LINE:
            self._skipping = True
            self._line.clear()
            return
        self._line.extend(part)

    def _handle(self, line: bytes) -> None:
        if not line.startswith(b"data:"):
            return
        try:
            event = json.loads(line[5:].strip())
        except (ValueError, RecursionError):
            return
        if not isinstance(event, dict):
            return
        kind = event.get("type")
        if kind == "message_start":
            message = event.get("message")
            inp, out = _usage_from(message)
            self.input_tokens = inp if inp is not None else self.input_tokens
            self.output_tokens = out if out is not None else self.output_tokens
        elif kind == "message_delta":
            inp, out = _usage_from(event)
            self.input_tokens = inp if inp is not None else self.input_tokens
            self.output_tokens = out if out is not None else self.output_tokens

    @property
    def seen(self) -> bool:
        return self.input_tokens is not None or self.output_tokens is not None


class ModelProxy:
    def __init__(self, *, verifier: Any, contexts: Any, client: httpx.AsyncClient, config: ModelProxyConfig, sink: UsageSink) -> None:
        self.verifier = verifier
        self.contexts = contexts
        self.client = client
        self.config = config
        self.sink = sink
        self._outcomes: Counter[str] = Counter()
        self._tokens: Counter[str] = Counter()
        self._latency_sum = 0.0
        self._latency_count = 0

    # --- bookkeeping -------------------------------------------------------------------------------------------------------------------

    def _outcome(self, outcome: str) -> None:
        self._outcomes[outcome] += 1

    def _record(self, identity: AgentIdentity, model: str, inp: int, out: int, stream: bool, outcome: str) -> None:
        self.sink.record(ModelUsage(identity.agent_id, identity.organization_id, model, inp, out, stream, outcome))
        self._outcomes[outcome] += 1
        self._tokens["input"] += inp
        self._tokens["output"] += out

    def _spend_refusal(self, spend: Any, model: str) -> JSONResponse | None:
        """B5c: refuse over the agent's daily dollar limit, using what the proxy MEASURED (never what an SDK reported). No limit (None) means no check. Fails closed: spend that could not be
        priced, or a model the price table does not know, is refused while a limit is set (a cost cannot be kept under a limit it cannot be measured against). A call's cost is known only after it
        ends and the figure reaches this process through core a few seconds later, so the limit can be overshot by the calls in flight and in that lag: documented in ADR 0025, bounded by max_tokens."""
        if spend is None:
            return None
        if spend.measured_micro_usd >= spend.limit_micro_usd:
            self._outcome("spend_limit")
            return _error(429, "rate_limit_error", "This agent has reached its daily model spend limit. It can call the model again after the day resets or an admin raises the limit.")
        if not spend.spend_known or _price_key(model) not in spend.priced_models:
            self._outcome("spend_unpriced")
            return _error(403, "permission_error", "This agent has a daily model spend limit and this call cannot be priced, so it is refused.")
        return None

    def render_prometheus(self) -> str:
        lines = ["# TYPE agentwall_model_proxy_requests_total counter"]
        for outcome, n in sorted(self._outcomes.items()):
            lines.append(f'agentwall_model_proxy_requests_total{{outcome="{outcome}"}} {n}')
        lines.append("# TYPE agentwall_model_proxy_tokens_total counter")
        for direction in ("input", "output"):
            lines.append(f'agentwall_model_proxy_tokens_total{{direction="{direction}"}} {self._tokens[direction]}')
        lines.append("# TYPE agentwall_model_proxy_overhead_seconds_sum counter")
        lines.append(f"agentwall_model_proxy_overhead_seconds_sum {self._latency_sum:.6f}")
        lines.append(f"agentwall_model_proxy_overhead_seconds_count {self._latency_count}")
        return "\n".join(lines) + "\n"

    # --- the request -------------------------------------------------------------------------------------------------------------------

    async def _read_body(self, request: Request) -> bytes | None:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.config.max_request_bytes:
            return None
        received = bytearray()
        async for chunk in request.stream():
            received.extend(chunk)
            if len(received) > self.config.max_request_bytes:
                return None
        return bytes(received)

    @staticmethod
    def _token(request: Request) -> str | None:
        header = request.headers.get("authorization", "")
        scheme, _, value = header.partition(" ")
        if scheme.lower() == "bearer" and value.strip() and " " not in value.strip():
            return value.strip()
        key = request.headers.get("x-api-key", "").strip()
        return key or None

    def _validate(self, raw: bytes) -> tuple[str, bool] | str:
        """(model, stream) for a good request, or the reason it is refused."""

        def reject(name: str) -> Any:
            raise ValueError(f"{name} is not valid JSON")

        try:
            body = json.loads(raw, parse_constant=reject)
        except (ValueError, RecursionError):
            return "The request body is not valid JSON."
        if not isinstance(body, dict):
            return "The request body must be a JSON object."
        model = body.get("model")
        if not isinstance(model, str) or not MODEL_PATTERN.match(model):
            return "model must be a plain model name."
        max_tokens = body.get("max_tokens")
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or not 1 <= max_tokens <= self.config.max_tokens_cap:
            return f"max_tokens must be a whole number from 1 to {self.config.max_tokens_cap}."
        stream = body.get("stream", False)
        if not isinstance(stream, bool):
            return "stream must be true or false."
        return model, stream

    async def handle(self, request: Request) -> Response:
        started = time.perf_counter()
        if self.config.provider_key is None:
            self._outcome("not_configured")
            return _error(503, "api_error", "The model proxy has no provider credential configured.")
        token = self._token(request)
        if token is None:
            self._outcome("unauthorized")
            return _error(401, "authentication_error", "Agent access token required.")
        try:
            identity = await self.verifier.verify(token)
        except KeyUnavailableError:
            self._outcome("keys_unavailable")
            return _error(503, "api_error", "Gateway cannot verify tokens right now.")
        except AgentAuthError:
            self._outcome("unauthorized")
            return _error(401, "authentication_error", "Invalid or expired agent access token.")

        raw = await self._read_body(request)
        if raw is None:
            self._outcome("too_large")
            return _error(413, "request_too_large", "The request is larger than this gateway accepts.")
        checked = self._validate(raw)
        if isinstance(checked, str):
            self._outcome("malformed")
            return _error(400, "invalid_request_error", checked)
        model, stream = checked

        try:
            context = await self.contexts.get(identity.agent_id, identity.organization_id, MODEL_SERVER_NAME)
        except AgentUnknownError:
            self._outcome("unknown_agent")
            return _error(401, "authentication_error", "Agent is not registered.")
        except ContextUnavailableError:
            self._outcome("context_unavailable")
            return _error(503, "api_error", "Passport service unavailable; request denied.")
        if context.status != "active":
            self._outcome("passport_inactive")
            return _error(403, "permission_error", f"Agent passport is {context.status}.")
        if identity.passport_version < context.passport_version:
            self._outcome("token_stale")
            return _error(401, "authentication_error", "Agent access token is out of date. Request a new one.")
        if (self.config.allowed_models and model not in self.config.allowed_models) or not context.covers_tool(model):
            self._outcome("model_denied")
            return _error(403, "permission_error", f"This agent may not use the model '{model}'.")

        refusal = self._spend_refusal(context.model_spend, model)
        if refusal is not None:
            return refusal

        headers = {"content-type": "application/json", "x-api-key": self.config.provider_key.get_secret_value(), "accept-encoding": "identity",
                   "anthropic-version": request.headers.get("anthropic-version", DEFAULT_ANTHROPIC_VERSION)}
        for name in PASS_REQUEST_HEADERS[1:]:
            if name in request.headers:
                headers[name] = request.headers[name]
        upstream = self.client.build_request(
            "POST", self.config.provider_url.rstrip("/") + "/v1/messages", content=raw, headers=headers,
            timeout=httpx.Timeout(self.config.total_timeout, connect=self.config.connect_timeout, read=self.config.stream_idle_timeout),
        )
        self._latency_sum += time.perf_counter() - started
        self._latency_count += 1
        try:
            response = await self.client.send(upstream, stream=True)
        except httpx.HTTPError as exc:
            logger.warning("Model provider unreachable", error_type=type(exc).__name__)
            self._record(identity, model, 0, 0, stream, "provider_unreachable")
            return _error(502, "api_error", "The model provider could not be reached.")

        if response.status_code == 200 and stream and response.headers.get("content-type", "").startswith("text/event-stream"):
            return self._stream(identity, model, response)
        return await self._whole(identity, model, stream, response)

    # --- the answer --------------------------------------------------------------------------------------------------------------------

    @staticmethod
    def _passed_headers(response: httpx.Response) -> dict[str, str]:
        return {name: response.headers[name] for name in PASS_RESPONSE_HEADERS if name in response.headers}

    async def _whole(self, identity: AgentIdentity, model: str, stream: bool, response: httpx.Response) -> Response:
        body = bytearray()
        try:
            async for chunk in response.aiter_raw():
                body.extend(chunk)
                if len(body) > self.config.max_response_bytes:
                    self._record(identity, model, 0, 0, stream, "response_too_large")
                    return _error(502, "api_error", "The model provider's answer was larger than this gateway accepts.")
        except httpx.HTTPError as exc:
            logger.warning("Model provider read failed", error_type=type(exc).__name__)
            self._record(identity, model, 0, 0, stream, "provider_unreachable")
            return _error(502, "api_error", "The model provider could not be reached.")
        finally:
            await response.aclose()

        status = response.status_code
        if status in (401, 403):
            # The gateway's own credential was refused: that is not the agent's problem and the answer might echo the key. Say nothing of it.
            logger.error("Model provider rejected the gateway credential", status=status)
            self._record(identity, model, 0, 0, stream, "provider_rejected_key")
            return _error(502, "api_error", "The model provider refused the gateway's credential.")
        if status >= 400:
            self._record(identity, model, 0, 0, stream, "provider_error")
            return Response(content=bytes(body), status_code=status, headers=self._passed_headers(response))
        try:
            parsed = json.loads(bytes(body))
        except (ValueError, RecursionError):
            self._record(identity, model, 0, 0, stream, "provider_invalid")
            return _error(502, "api_error", "The model provider returned something that is not JSON.")
        inp, out = _usage_from(parsed)
        outcome = "ok" if inp is not None or out is not None else "usage_not_reported"
        self._record(identity, model, inp or 0, out or 0, stream, outcome)
        return Response(content=bytes(body), status_code=status, headers=self._passed_headers(response))

    def _stream(self, identity: AgentIdentity, model: str, response: httpx.Response) -> Response:
        parser = StreamUsageParser()
        config = self.config

        async def relay() -> AsyncIterator[bytes]:
            sent = 0
            outcome = "ok"
            iterator = response.aiter_raw().__aiter__()
            try:
                while True:
                    try:
                        chunk = await asyncio.wait_for(iterator.__anext__(), timeout=config.stream_idle_timeout)
                    except StopAsyncIteration:
                        break
                    sent += len(chunk)
                    if sent > config.max_stream_bytes:
                        outcome = "stream_too_large"
                        raise RuntimeError("model stream exceeded its size cap")
                    parser.feed(chunk)
                    yield chunk
            except (httpx.HTTPError, asyncio.TimeoutError):
                outcome = "stream_interrupted"
                raise
            except asyncio.CancelledError:
                outcome = "stream_cancelled"
                raise
            except GeneratorExit:
                outcome = "stream_cancelled"
                raise
            finally:
                await response.aclose()
                if outcome == "ok" and not parser.seen:
                    outcome = "usage_not_reported"
                self._record(identity, model, parser.input_tokens or 0, parser.output_tokens or 0, True, outcome)

        return StreamingResponse(relay(), status_code=response.status_code, headers=self._passed_headers(response))


def mount_model_proxy(app: FastAPI, proxy: ModelProxy) -> None:
    """Adds the proxy route. A disabled proxy adds nothing: the path does not exist."""
    if not proxy.config.enabled:
        return

    @app.post(ROUTE, include_in_schema=False)
    async def model_proxy(request: Request) -> Response:
        return await proxy.handle(request)
