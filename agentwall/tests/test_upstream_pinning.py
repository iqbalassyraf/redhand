"""
The gateway connects to the address its destination check approved (H2.2). One DNS lookup per call, every answer public, the request goes to a
checked address with the original Host and TLS name, an unopenable connection moves to the next checked address, and one deadline covers the
whole call. The URL rules are held to the same vectors as core's webhook guard.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentwall.src.gateway.upstream import (
    Attempt,
    DestinationBlockedError,
    UpstreamError,
    UpstreamForwarder,
    resolve_destination,
)

VECTORS = json.loads((Path(__file__).resolve().parent / "data" / "outbound_url_vectors.json").read_text())
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"
RPC = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
OK_BODY = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}


def resolver_returning(*addresses: str) -> Any:
    calls: list[tuple[str, int]] = []

    async def resolve(host: str, port: int) -> list[str]:
        calls.append((host, port))
        return list(addresses)

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


# --- one rule set for core and the gateway --------------------------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("case", VECTORS["static"], ids=[c["url"] or "empty" for c in VECTORS["static"]])
async def test_static_checks_match_the_shared_vectors(case: dict[str, Any]) -> None:
    resolver = resolver_returning(PUBLIC_V4)
    if case["ok"]:
        await resolve_destination(case["url"], False, resolver=resolver)
    else:
        with pytest.raises(DestinationBlockedError):
            await resolve_destination(case["url"], False, resolver=resolver)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", VECTORS["resolved"], ids=[f"{c['host']}-{'-'.join(c['addresses']) or 'none'}" for c in VECTORS["resolved"]])
async def test_resolved_addresses_must_all_be_public(case: dict[str, Any]) -> None:
    resolver = resolver_returning(*case["addresses"])
    if case["ok"]:
        await resolve_destination(f"https://{case['host']}/mcp", False, resolver=resolver)
    else:
        with pytest.raises(UpstreamError):
            await resolve_destination(f"https://{case['host']}/mcp", False, resolver=resolver)


# --- pinning ---------------------------------------------------------------------------------------------------------------------------

def forwarder(handler: Any, resolver: Any, *, pin: bool = True, total_timeout: float = 5.0) -> UpstreamForwarder:
    return UpstreamForwarder(
        allow_insecure=False, max_response_bytes=100_000, connect_timeout=1, total_timeout=total_timeout, pin_connections=pin,
        resolver=resolver, http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


async def send(fwd: UpstreamForwarder, url: str = "https://mcp.example.com/mcp?x=1") -> Any:
    return await fwd.send(url=url, message=RPC, client_headers={}, upstream_authorization=None)


@pytest.mark.asyncio
async def test_the_request_goes_to_the_checked_address_with_the_original_host_and_tls_name() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=OK_BODY)

    resolver = resolver_returning(PUBLIC_V4)
    result = await send(forwarder(handler, resolver), "https://mcp.example.com:8443/mcp?x=1")
    assert result.message == OK_BODY
    assert len(seen) == 1 and resolver.calls == [("mcp.example.com", 8443)]
    request = seen[0]
    assert request.url.host == PUBLIC_V4 and request.url.port == 8443 and request.url.path == "/mcp" and request.url.query == b"x=1"
    assert request.headers["host"] == "mcp.example.com:8443"
    assert request.extensions["sni_hostname"] == "mcp.example.com"


@pytest.mark.asyncio
async def test_a_second_dns_answer_is_never_used() -> None:
    """DNS rebinding: the first answer is public, any later answer would be the metadata address. There is no later lookup."""
    answers = [[PUBLIC_V4], ["169.254.169.254"], ["169.254.169.254"]]
    calls: list[str] = []

    async def rebinding(host: str, port: int) -> list[str]:
        calls.append(host)
        return answers[len(calls) - 1]

    targets: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        targets.append(request.url.host)
        return httpx.Response(200, json=OK_BODY)

    await send(forwarder(handler, rebinding))
    assert calls == ["mcp.example.com"], "the name must be looked up exactly once per call"
    assert targets == [PUBLIC_V4]


@pytest.mark.asyncio
async def test_without_pinning_the_name_is_used_after_the_same_check() -> None:
    targets: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        targets.append(request.url.host)
        return httpx.Response(200, json=OK_BODY)

    await send(forwarder(handler, resolver_returning(PUBLIC_V4), pin=False))
    assert targets == ["mcp.example.com"]
    with pytest.raises(DestinationBlockedError):  # the kill switch never turns the check off
        await send(forwarder(handler, resolver_returning("10.0.0.5"), pin=False))


@pytest.mark.asyncio
async def test_one_private_answer_refuses_the_call_and_nothing_is_sent() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=OK_BODY)

    with pytest.raises(DestinationBlockedError):
        await send(forwarder(handler, resolver_returning(PUBLIC_V4, "10.0.0.5")))
    assert sent == []


@pytest.mark.asyncio
async def test_an_unresolvable_name_is_an_upstream_error() -> None:
    async def broken(host: str, port: int) -> list[str]:
        raise OSError("no such host")

    with pytest.raises(UpstreamError, match="could not be resolved"):
        await send(forwarder(lambda r: httpx.Response(200), broken))


@pytest.mark.asyncio
async def test_ipv4_is_tried_first_and_a_connection_that_cannot_open_moves_to_the_next_checked_address() -> None:
    tried: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        tried.append(request.url.host)
        if len(tried) == 1:
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200, json=OK_BODY)

    result = await send(forwarder(handler, resolver_returning(PUBLIC_V6, PUBLIC_V4, "93.184.216.35")))
    assert result.message == OK_BODY
    assert tried == [PUBLIC_V4, "93.184.216.35"]


@pytest.mark.asyncio
async def test_only_an_unopened_connection_is_retried() -> None:
    tried: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        tried.append(request.url.host)
        raise httpx.ReadError("reset after sending", request=request)

    with pytest.raises(UpstreamError, match="unreachable"):
        await send(forwarder(handler, resolver_returning(PUBLIC_V4, "93.184.216.35")))
    assert len(tried) == 1, "a request that may have been delivered must not be sent again"


@pytest.mark.asyncio
async def test_attempts_are_capped() -> None:
    tried: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        tried.append(request.url.host)
        raise httpx.ConnectError("refused", request=request)

    many = [f"93.184.216.{n}" for n in range(1, 9)]
    with pytest.raises(UpstreamError):
        await send(forwarder(handler, resolver_returning(*many)))
    assert len(tried) == 3


# --- one deadline for the whole call ---------------------------------------------------------------------------------------------------

class _SlowDrip(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        for _ in range(100):
            await asyncio.sleep(0.05)
            yield b" "

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_a_server_that_answers_one_byte_at_a_time_cannot_hold_the_call_open() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=_SlowDrip())

    started = asyncio.get_running_loop().time()
    with pytest.raises(UpstreamError, match="did not answer in time"):
        await send(forwarder(handler, resolver_returning(PUBLIC_V4), total_timeout=0.3))
    assert asyncio.get_running_loop().time() - started < 1.5


@pytest.mark.asyncio
async def test_a_slow_lookup_counts_against_the_same_deadline() -> None:
    async def slow(host: str, port: int) -> list[str]:
        await asyncio.sleep(5)
        return [PUBLIC_V4]

    with pytest.raises(UpstreamError, match="did not answer in time"):
        await send(forwarder(lambda r: httpx.Response(200, json=OK_BODY), slow, total_timeout=0.2))


# --- real TLS --------------------------------------------------------------------------------------------------------------------------

def _self_signed(tmp_path: Path, name: str) -> tuple[Path, Path]:
    import shutil
    import subprocess

    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}"], check=True, capture_output=True)
    return key, cert


def _serve_tls(key: Path, cert: Path) -> tuple[Any, int]:
    import http.server
    import ssl
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"host": self.headers.get("Host")}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: Any) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


@pytest.mark.asyncio
async def test_real_tls_is_verified_against_the_original_name_while_connecting_to_the_pinned_address(tmp_path: Path) -> None:
    import ssl

    key, cert = _self_signed(tmp_path, "pinned.test")
    server, port = _serve_tls(key, cert)
    try:
        trust = ssl.create_default_context(cafile=str(cert))

        async def call(sni: str) -> Any:
            async with httpx.AsyncClient(verify=trust, follow_redirects=False) as client:
                fwd = UpstreamForwarder(
                    allow_insecure=False, max_response_bytes=100_000, connect_timeout=2, total_timeout=5, http_client=client
                )
                attempt = Attempt(f"https://127.0.0.1:{port}/mcp", {"Host": f"pinned.test:{port}"}, {"sni_hostname": sni})
                return await fwd._exchange([attempt], b"{}", {"Content-Type": "application/json"})  # noqa: SLF001

        status, _, _, chunks = await call("pinned.test")
        assert status == 200 and json.loads(b"".join(chunks))["result"]["host"] == f"pinned.test:{port}"
        with pytest.raises(httpx.HTTPError):  # a certificate for another name is refused: pinning does not skip verification
            await call("attacker.test")
    finally:
        server.shutdown()


def test_an_ipv4_mapped_address_is_judged_as_the_ipv4_address_on_every_supported_python() -> None:
    """Python 3.13 already does this inside is_global; 3.11 and 3.12 do not. A stand-in that reports every address as global proves the
    explicit unwrap, whatever interpreter runs the test."""
    import ipaddress

    from agentwall.src.gateway.upstream import _is_public  # noqa: PLC2701

    class OldInterpreterAddress(ipaddress.IPv6Address):
        @property
        def is_global(self) -> bool:
            return True

    assert _is_public(OldInterpreterAddress("::ffff:10.0.0.1")) is False
    assert _is_public(OldInterpreterAddress("::ffff:169.254.169.254")) is False
    assert _is_public(OldInterpreterAddress("::ffff:93.184.216.34")) is True
