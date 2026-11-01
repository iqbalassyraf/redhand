"""
Forwarding JSON-RPC messages to a customer's remote MCP server (Streamable HTTP).

Safety properties:
- Destination check before every request: http(s) only, no credentials in the URL, and
  every resolved address must be public unless insecure upstreams are explicitly allowed
  (development). Resolution happens per request because DNS can change.
  Residual risk: DNS rebinding between this check and httpx's own resolution. Pinning
  the connection to the checked address is a tracked follow-up.
- Redirects are never followed.
- Response size and time are bounded; anything unexpected is an error, never a
  fabricated success.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import json
import socket
from typing import Any
from urllib.parse import urlsplit

import httpx
import structlog

logger = structlog.get_logger(__name__)

FORWARDED_REQUEST_HEADERS = ("mcp-session-id", "mcp-protocol-version", "last-event-id")
FORWARDED_RESPONSE_HEADERS = ("mcp-session-id",)


class UpstreamError(Exception):
    """The upstream could not be reached safely or did not return a usable answer."""


class DestinationBlockedError(UpstreamError):
    """The upstream URL resolves to a destination the gateway must not contact."""


@dataclass(frozen=True, slots=True)
class UpstreamResult:
    status_code: int
    message: dict[str, Any] | None  # the JSON-RPC response matching the request, if any
    headers: dict[str, str]


async def check_destination(url: str, allow_insecure: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise DestinationBlockedError("Upstream URL is not an absolute http(s) URL.")
    if parts.username or parts.password:
        raise DestinationBlockedError("Upstream URL must not embed credentials.")
    if allow_insecure:
        return
    if parts.scheme != "https":
        raise DestinationBlockedError("Upstream URL must use https.")
    port = parts.port or 443
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            parts.hostname, port, type=socket.SOCK_STREAM
        )
    except OSError as exc:
        raise UpstreamError("Upstream host could not be resolved.") from exc
    if not infos:
        raise UpstreamError("Upstream host could not be resolved.")
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global:
            raise DestinationBlockedError("Upstream resolves to a non-public address.")


def parse_sse_messages(body: str) -> list[dict[str, Any]]:
    """Extracts JSON payloads from a text/event-stream body (one per event)."""
    messages: list[dict[str, Any]] = []
    for block in body.replace("\r\n", "\n").split("\n\n"):
        data_lines = [line[5:].lstrip() for line in block.split("\n") if line.startswith("data:")]
        if not data_lines:
            continue
        try:
            payload = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            messages.append(payload)
    return messages


class UpstreamForwarder:
    def __init__(
        self,
        *,
        allow_insecure: bool,
        max_response_bytes: int,
        connect_timeout: float,
        total_timeout: float,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._allow_insecure = allow_insecure
        self._max_bytes = max_response_bytes
        self._http = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(total_timeout, connect=connect_timeout),
            follow_redirects=False,
        )

    async def send(
        self,
        *,
        url: str,
        message: dict[str, Any],
        client_headers: dict[str, str],
        upstream_authorization: str | None,
    ) -> UpstreamResult:
        await check_destination(url, self._allow_insecure)

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "RedHand-Gateway/1.0",
        }
        for name in FORWARDED_REQUEST_HEADERS:
            if name in client_headers:
                headers[name] = client_headers[name]
        if upstream_authorization:
            headers["Authorization"] = upstream_authorization

        try:
            async with self._http.stream("POST", url, json=message, headers=headers) as resp:
                chunks: list[bytes] = []
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > self._max_bytes:
                        raise UpstreamError("Upstream response exceeded the size limit.")
                    chunks.append(chunk)
                status_code = resp.status_code
                content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                passthrough = {
                    name: resp.headers[name] for name in FORWARDED_RESPONSE_HEADERS if name in resp.headers
                }
        except httpx.HTTPError as exc:
            logger.warning("Upstream MCP server unreachable", error_type=type(exc).__name__)
            raise UpstreamError("Upstream MCP server is unreachable.") from exc

        if 300 <= status_code < 400:
            raise UpstreamError("Upstream attempted a redirect, which is not followed.")
        if status_code >= 400:
            raise UpstreamError(f"Upstream MCP server returned HTTP {status_code}.")

        if "id" not in message:  # notification or response from client: no reply expected
            return UpstreamResult(status_code=status_code, message=None, headers=passthrough)

        body = b"".join(chunks).decode("utf-8", errors="replace")
        if content_type == "text/event-stream":
            candidates = parse_sse_messages(body)
        else:
            try:
                parsed = json.loads(body) if body else None
            except json.JSONDecodeError as exc:
                raise UpstreamError("Upstream returned invalid JSON.") from exc
            candidates = [parsed] if isinstance(parsed, dict) else []

        for candidate in candidates:
            if candidate.get("id") == message["id"] and ("result" in candidate or "error" in candidate):
                return UpstreamResult(status_code=status_code, message=candidate, headers=passthrough)
        raise UpstreamError("Upstream did not return a response to the request.")
