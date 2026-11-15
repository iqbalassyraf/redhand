"""
Calling a URL that someone else supplied (CLAUDE.md section 5.4, SSRF). Webhook URLs reach core from agent SDKs (`resume_webhook_url`,
`notification_webhook_url`) and from organization settings (`siem_webhook_url`); core POSTs to them from inside its own network, so each
is a request core makes on a stranger's behalf. Rules, in this order:
  1. static: an absolute https URL, no credentials in it, not a local or internal name, a literal address must be public;
  2. resolve, then check: every address the name resolves to must be public (a name that resolves to a private address is refused);
  3. connect to the address that was checked, not to the name: the request goes to the IP with the original Host header and TLS name
     (httpx's `sni_hostname` extension), so there is no second lookup an attacker could answer differently (DNS rebinding);
  4. no redirects, a hard total deadline, and a cap on the response size.
The gateway has the same checks for MCP upstreams (agentwall/src/gateway/upstream.py); the two copies are kept in step by a test that runs one
shared vector file through both (agentwall/tests/data/outbound_url_vectors.json).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
import ipaddress
import socket
from urllib.parse import SplitResult, urlsplit

import httpx

MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 5.0
Resolver = Callable[[str, int], Awaitable[list[str]]]


class OutboundError(Exception):
    """A request to a supplied URL was not made, or did not complete usefully. The message is fixed wording: it never contains the URL."""


class OutboundBlockedError(OutboundError):
    """The URL is not one core may call (not https, credentials, local or internal name, or a non-public address)."""


@dataclass(frozen=True, slots=True)
class OutboundResponse:
    status_code: int
    content: bytes

    def raise_for_status(self) -> None:
        if self.status_code >= 300:  # redirects are never followed, so a 3xx is a failure too
            raise OutboundError(f"The server answered HTTP {self.status_code}.")


def _is_local_name(host: str) -> bool:
    return host == "localhost" or host.endswith((".localhost", ".internal", ".local", ".localdomain"))


def check_url(url: str, *, allow_insecure: bool = False) -> SplitResult:
    """Static checks, no network. Returns the parsed URL. `allow_insecure` (development only) permits http and non-public hosts."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        _ = parts.port  # raises ValueError for a port outside 0..65535
    except ValueError as exc:
        raise OutboundBlockedError("The URL is not valid.") from exc
    if parts.scheme not in ("https", "http") or not host:
        raise OutboundBlockedError("The URL must be an absolute http(s) URL.")
    if parts.username or parts.password:
        raise OutboundBlockedError("The URL must not contain credentials.")
    if allow_insecure:
        return parts
    if parts.scheme != "https":
        raise OutboundBlockedError("The URL must use https.")
    if _is_local_name(host):
        raise OutboundBlockedError("The URL must be publicly reachable.")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        return parts  # a name: the resolved addresses are checked next
    if not _is_public(literal):
        raise OutboundBlockedError("The URL must be publicly reachable.")
    return parts


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped  # ::ffff:10.0.0.1 is the private address 10.0.0.1
    return address.is_global and not address.is_multicast


def insecure_webhooks_allowed() -> bool:
    """The development-only switch (ALLOW_INSECURE_WEBHOOK_URLS). Read per call so a test or a restart changes it without a code path."""
    from redhand_core.config import get_settings

    return bool(get_settings().ALLOW_INSECURE_WEBHOOK_URLS)


def record_blocked(purpose: str) -> None:
    """Counts a webhook that core refused to call (redhand_outbound_blocked_total{purpose}); the caller logs the host only."""
    from redhand_core.services.metrics import get_metrics

    get_metrics().increment_counter("redhand_outbound_blocked_total", labels={"purpose": purpose})


async def system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


async def resolve_public(host: str, port: int, resolver: Resolver | None = None) -> list[str]:
    """Every address the name resolves to, after checking that ALL of them are public. One private answer refuses the whole name."""
    try:
        addresses = await (resolver or system_resolver)(host, port)
    except OSError as exc:
        raise OutboundError("The host could not be resolved.") from exc
    if not addresses:
        raise OutboundError("The host could not be resolved.")
    for text in addresses:
        try:
            address = ipaddress.ip_address(text.split("%")[0])
        except ValueError as exc:
            raise OutboundBlockedError("The host resolved to an address that could not be read.") from exc
        if not _is_public(address):
            raise OutboundBlockedError("The URL must be publicly reachable.")
    return addresses


def _pinned_url(parts: SplitResult, address: str) -> str:
    ip = ipaddress.ip_address(address.split("%")[0])
    literal = f"[{ip}]" if ip.version == 6 else str(ip)
    port = f":{parts.port}" if parts.port else ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{literal}{port}{parts.path or '/'}{query}"


async def post_json(
    url: str,
    payload: object,
    *,
    allow_insecure: bool = False,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
    resolver: Resolver | None = None,
    client: httpx.AsyncClient | None = None,
) -> OutboundResponse:
    """POSTs JSON to a supplied URL under the rules above. Raises OutboundError (never httpx errors) with fixed, URL-free wording."""
    parts = check_url(url, allow_insecure=allow_insecure)
    host = (parts.hostname or "").rstrip(".")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    target = url
    request_headers = dict(headers or {})
    extensions: dict[str, object] = {}
    if not allow_insecure:
        try:
            ipaddress.ip_address(host)
            literal = True
        except ValueError:
            literal = False
        if not literal:
            address = (await resolve_public(host, port, resolver))[0]  # the first checked address; the name is not looked up again
            target = _pinned_url(parts, address)
            request_headers["Host"] = host if not parts.port else f"{host}:{parts.port}"
            extensions["sni_hostname"] = host
    owns_client = client is None
    http = client or httpx.AsyncClient(follow_redirects=False)
    try:
        return await send_post(http, target, payload, request_headers, extensions, timeout, max_response_bytes)
    finally:
        if owns_client:
            await http.aclose()


async def send_post(
    http: httpx.AsyncClient, target: str, payload: object, headers: dict[str, str], extensions: dict[str, object], timeout: float,
    max_response_bytes: int,
) -> OutboundResponse:
    """The request itself, after every check: one POST, no redirects, a hard total deadline, a capped body, URL-free errors."""
    try:
        async with asyncio.timeout(timeout):
            async with http.stream("POST", target, json=payload, headers=headers, extensions=extensions) as response:
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_response_bytes:
                        raise OutboundError("The response was too large.")
                return OutboundResponse(response.status_code, bytes(body))
    except TimeoutError as exc:
        raise OutboundError("The request timed out.") from exc
    except httpx.HTTPError as exc:
        raise OutboundError(f"The request failed ({type(exc).__name__}).") from exc
