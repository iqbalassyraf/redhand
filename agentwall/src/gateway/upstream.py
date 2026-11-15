"""
Forwarding JSON-RPC messages to a customer's remote MCP server (Streamable HTTP).

Safety properties:
- Destination check before every request: http(s) only, no credentials in the URL, no
  local or internal names, and every resolved address must be public unless insecure
  upstreams are explicitly allowed (development). Resolution happens per request because
  DNS can change, and exactly once: the connection then goes to a checked address (IPv4
  first), with the original Host header and the original name for the TLS certificate
  check, so a second, different DNS answer (DNS rebinding) is never used. A connection
  that cannot be opened is retried on the next checked address, never on a new lookup.
  UPSTREAM_PIN_ENABLED=false (kill switch) goes back to connecting by name after the check.
- Redirects are never followed.
- Response size is bounded and the whole call (every connection attempt and the body)
  has one deadline, so a server that answers one byte at a time cannot hold a call open;
  anything unexpected is an error, never a fabricated success.
- The same URL rules as core's webhook guard (services/redhand-core/.../net/outbound.py);
  one shared vector file keeps the two in step (tests/data/outbound_url_vectors.json).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
import ipaddress
import json
import socket
from typing import Any
from urllib.parse import SplitResult, urlsplit

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


Resolver = Callable[[str, int], Awaitable[list[str]]]
MAX_CONNECT_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class Attempt:
    """One way to reach the upstream: the URL to call, the headers it needs, and httpx extensions (the TLS name when pinned)."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    extensions: dict[str, object] = field(default_factory=dict)


async def system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _is_local_name(host: str) -> bool:
    return host == "localhost" or host.endswith((".localhost", ".internal", ".local", ".localdomain"))


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped  # ::ffff:10.0.0.1 is the private address 10.0.0.1
    return address.is_global and not address.is_multicast


def _static_checks(url: str, allow_insecure: bool) -> tuple[SplitResult, str]:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        _ = parts.port  # raises ValueError for a port outside 0..65535
    except ValueError as exc:
        raise DestinationBlockedError("Upstream URL is not valid.") from exc
    if parts.scheme not in ("https", "http") or not host:
        raise DestinationBlockedError("Upstream URL is not an absolute http(s) URL.")
    if parts.username or parts.password:
        raise DestinationBlockedError("Upstream URL must not embed credentials.")
    if allow_insecure:
        return parts, host
    if parts.scheme != "https":
        raise DestinationBlockedError("Upstream URL must use https.")
    if _is_local_name(host):
        raise DestinationBlockedError("Upstream resolves to a non-public address.")
    return parts, host


def _pinned_url(parts: SplitResult, address: str) -> str:
    ip = ipaddress.ip_address(address.split("%")[0])
    literal = f"[{ip}]" if ip.version == 6 else str(ip)
    port = f":{parts.port}" if parts.port else ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{literal}{port}{parts.path or '/'}{query}"


async def resolve_destination(
    url: str, allow_insecure: bool, *, pin: bool = True, resolver: Resolver | None = None
) -> list[Attempt]:
    """The checks, then the ways to connect. One DNS lookup; every address it returned must be public (one private answer refuses the
    whole name). With `pin`, each attempt connects to a checked address and keeps the original Host and TLS name."""
    parts, host = _static_checks(url, allow_insecure)
    if allow_insecure:
        return [Attempt(url)]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:  # a literal address: nothing to resolve, and it is not public (or the check below refuses it)
        if not _is_public(ipaddress.ip_address(host)):
            raise DestinationBlockedError("Upstream resolves to a non-public address.")
        return [Attempt(url)]
    port = parts.port or 443
    try:
        texts = await (resolver or system_resolver)(host, port)
    except OSError as exc:
        raise UpstreamError("Upstream host could not be resolved.") from exc
    if not texts:
        raise UpstreamError("Upstream host could not be resolved.")
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for text in texts:
        try:
            address = ipaddress.ip_address(text.split("%")[0])
        except ValueError as exc:
            raise DestinationBlockedError("Upstream resolved to an address that could not be read.") from exc
        if not _is_public(address):
            raise DestinationBlockedError("Upstream resolves to a non-public address.")
        addresses.append(address)
    if not pin:
        return [Attempt(url)]
    addresses.sort(key=lambda a: a.version)  # IPv4 first: an IPv6 address a host cannot route would otherwise fail the call
    seen: list[str] = []
    for address in addresses:
        if str(address) not in seen:
            seen.append(str(address))
    host_header = host if not parts.port else f"{host}:{parts.port}"
    return [
        Attempt(_pinned_url(parts, text), {"Host": host_header}, {"sni_hostname": host})
        for text in seen[:MAX_CONNECT_ATTEMPTS]
    ]


async def check_destination(url: str, allow_insecure: bool, resolver: Resolver | None = None) -> None:
    await resolve_destination(url, allow_insecure, resolver=resolver)


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
        pin_connections: bool = True,
        resolver: Resolver | None = None,
    ) -> None:
        self._allow_insecure = allow_insecure
        self._max_bytes = max_response_bytes
        self._total_timeout = total_timeout
        self._pin = pin_connections
        self._resolver = resolver
        self._http = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(total_timeout, connect=connect_timeout),
            follow_redirects=False,
        )

    async def _exchange(
        self, attempts: list[Attempt], content: bytes, headers: dict[str, str]
    ) -> tuple[int, str, dict[str, str], list[bytes]]:
        """Sends the request to the first attempt that connects. Only a connection that could not be opened moves on to the next checked
        address (nothing was sent, so nothing is repeated); any other failure ends the call."""
        last: httpx.HTTPError | None = None
        for attempt in attempts:
            try:
                async with self._http.stream(
                    "POST", attempt.url, content=content, headers={**headers, **attempt.headers}, extensions=attempt.extensions
                ) as resp:
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > self._max_bytes:
                            raise UpstreamError("Upstream response exceeded the size limit.")
                        chunks.append(chunk)
                    content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                    passthrough = {name: resp.headers[name] for name in FORWARDED_RESPONSE_HEADERS if name in resp.headers}
                    return resp.status_code, content_type, passthrough, chunks
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last = exc
        if last is None:
            raise UpstreamError("Upstream MCP server is unreachable.")
        raise last

    async def send(
        self,
        *,
        url: str,
        message: dict[str, Any],
        client_headers: dict[str, str],
        upstream_authorization: str | None,
    ) -> UpstreamResult:
        # Encode once, here, with the same options httpx uses for `json=`, so a value that cannot be sent (NaN, infinity, an integer of more
        # than 4,300 digits, text that is not valid UTF-8) is an upstream error and never an exception out of the gateway.
        try:
            content = json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (ValueError, TypeError, RecursionError) as exc:
            raise UpstreamError("The request could not be encoded.") from exc

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
            async with asyncio.timeout(self._total_timeout):  # one deadline: the lookup, every connection attempt and the whole body
                attempts = await resolve_destination(url, self._allow_insecure, pin=self._pin, resolver=self._resolver)
                status_code, content_type, passthrough, chunks = await self._exchange(attempts, content, headers)
        except TimeoutError as exc:
            logger.warning("Upstream MCP server did not finish in time", limit_seconds=self._total_timeout)
            raise UpstreamError("Upstream MCP server did not answer in time.") from exc
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
