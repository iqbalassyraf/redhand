"""
Outbound calls to a URL someone else supplied (H2.1, CLAUDE.md section 5.4): the static checks, resolve-then-check, the pinned connection
(no second lookup, so no DNS rebinding), redirects, size and time limits, and that no error text ever contains the URL.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from redhand_core.net.outbound import (
    OutboundBlockedError,
    OutboundError,
    check_url,
    post_json,
    resolve_public,
)

VECTORS = json.loads((Path(__file__).resolve().parents[3] / "agentwall" / "tests" / "data" / "outbound_url_vectors.json").read_text())
SECRET = "SuperSecretWebhookToken0123456789"
PUBLIC = "93.184.216.34"


def resolver_returning(*addresses: str) -> Any:
    calls: list[tuple[str, int]] = []

    async def resolve(host: str, port: int) -> list[str]:
        calls.append((host, port))
        return list(addresses)

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


@pytest.mark.parametrize("case", VECTORS["static"], ids=[c["url"] or "empty" for c in VECTORS["static"]])
def test_static_checks_match_the_shared_vectors(case: dict[str, Any]) -> None:
    if case["ok"]:
        check_url(case["url"])
    else:
        with pytest.raises(OutboundBlockedError):
            check_url(case["url"])


@pytest.mark.parametrize("case", VECTORS["resolved"], ids=[f"{c['host']}-{'-'.join(c['addresses']) or 'none'}" for c in VECTORS["resolved"]])
def test_resolved_addresses_must_all_be_public(case: dict[str, Any]) -> None:
    resolver = resolver_returning(*case["addresses"])
    if case["ok"]:
        assert asyncio.run(resolve_public(case["host"], 443, resolver)) == case["addresses"]
    else:
        with pytest.raises(OutboundError):
            asyncio.run(resolve_public(case["host"], 443, resolver))


def test_the_insecure_flag_is_development_only_and_still_refuses_credentials() -> None:
    check_url("http://localhost:8099/hook", allow_insecure=True)
    with pytest.raises(OutboundBlockedError):
        check_url("http://user:pw@localhost/hook", allow_insecure=True)
    with pytest.raises(OutboundBlockedError):
        check_url("http://localhost:8099/hook")


# --- the request itself ---------------------------------------------------------------------------------------------------------------

def mock_client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_the_connection_goes_to_the_checked_address_with_the_original_host_and_tls_name() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    resolver = resolver_returning(PUBLIC)
    response = asyncio.run(post_json("https://hooks.example.com:8443/a/b?c=d", {"x": 1}, resolver=resolver, client=mock_client(handler)))
    assert response.status_code == 200 and response.content == b"ok"
    (request,) = seen
    assert request.url.host == PUBLIC and request.url.port == 8443 and request.url.path == "/a/b" and request.url.query == b"c=d"
    assert request.headers["host"] == "hooks.example.com:8443"
    assert request.extensions["sni_hostname"] == "hooks.example.com"
    assert json.loads(request.content) == {"x": 1}


def test_the_name_is_resolved_once_so_a_second_answer_cannot_redirect_the_call() -> None:
    answers = iter([[PUBLIC], ["127.0.0.1"]])  # a rebinding server: public the first time, loopback the second
    calls = 0

    async def resolver(host: str, port: int) -> list[str]:
        nonlocal calls
        calls += 1
        return next(answers)

    targets: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        targets.append(request.url.host)
        return httpx.Response(200)

    asyncio.run(post_json("https://rebind.example.com/x", {}, resolver=resolver, client=mock_client(handler)))
    assert calls == 1 and targets == [PUBLIC]


def test_a_name_with_one_private_address_is_refused_before_any_request() -> None:
    sent: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(1)
        return httpx.Response(200)

    with pytest.raises(OutboundBlockedError):
        asyncio.run(post_json("https://rebind.example.com/x", {}, resolver=resolver_returning(PUBLIC, "10.0.0.5"), client=mock_client(handler)))
    assert sent == []


def test_an_ipv6_address_is_pinned_in_brackets() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    asyncio.run(post_json("https://v6.example.com/x", {}, resolver=resolver_returning("2606:4700:4700::1111"), client=mock_client(handler)))
    assert seen[0].url.host == "2606:4700:4700::1111"


def test_a_redirect_is_never_followed_and_counts_as_a_failure() -> None:
    hops: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hops.append(str(request.url.host))
        return httpx.Response(302, headers={"Location": "https://169.254.169.254/latest/meta-data/"})

    response = asyncio.run(post_json("https://hooks.example.com/x", {}, resolver=resolver_returning(PUBLIC), client=mock_client(handler)))
    assert response.status_code == 302 and hops == [PUBLIC]  # one request only
    with pytest.raises(OutboundError):
        response.raise_for_status()


def test_an_oversized_response_is_cut_off() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5000)

    with pytest.raises(OutboundError, match="too large"):
        asyncio.run(post_json("https://hooks.example.com/x", {}, resolver=resolver_returning(PUBLIC), client=mock_client(handler), max_response_bytes=1000))


def test_a_slow_server_is_cut_off_at_the_total_deadline() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(2)
        return httpx.Response(200)

    with pytest.raises(OutboundError, match="timed out"):
        asyncio.run(post_json("https://hooks.example.com/x", {}, resolver=resolver_returning(PUBLIC), client=mock_client(handler), timeout=0.1))


def test_errors_never_contain_the_url() -> None:
    url = f"https://hooks.example.com/services/{SECRET}?token={SECRET}"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)

    for failing in (
        post_json(url, {}, resolver=resolver_returning(PUBLIC), client=mock_client(handler)),
        post_json(f"http://x.example.com/{SECRET}", {}),
        post_json(f"https://u:p@x.example.com/{SECRET}", {}),
        post_json(f"https://127.0.0.1/{SECRET}", {}),
    ):
        with pytest.raises(OutboundError) as caught:
            asyncio.run(failing)
        assert SECRET not in str(caught.value)


def test_a_literal_public_address_is_called_directly_without_resolution() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    resolver = resolver_returning("10.0.0.1")  # must never be asked
    asyncio.run(post_json(f"https://{PUBLIC}/x", {}, resolver=resolver, client=mock_client(handler)))
    assert resolver.calls == [] and seen[0].url.host == PUBLIC  # type: ignore[attr-defined]


# --- real TLS: the certificate is checked against the original name while the socket goes to the pinned address ----------------------------------

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
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            body = json.dumps({"host": self.headers.get("Host")}).encode()
            self.send_response(200)
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


def test_real_tls_is_verified_against_the_original_name_while_connecting_to_the_pinned_address(tmp_path: Path) -> None:
    import ssl

    from redhand_core.net.outbound import send_post

    key, cert = _self_signed(tmp_path, "pinned.test")
    server, port = _serve_tls(key, cert)
    try:
        trust = ssl.create_default_context(cafile=str(cert))

        async def call(sni: str) -> Any:
            async with httpx.AsyncClient(verify=trust, follow_redirects=False) as http:
                return await send_post(http, f"https://127.0.0.1:{port}/hook", {"a": 1}, {"Host": f"pinned.test:{port}"},
                                       {"sni_hostname": sni}, 5.0, 4096)

        ok = asyncio.run(call("pinned.test"))
        assert ok.status_code == 200 and json.loads(ok.content)["host"] == f"pinned.test:{port}"  # the socket went to 127.0.0.1, the name was pinned.test
        with pytest.raises(OutboundError):  # a certificate for another name is refused: verification is not skipped when the address is pinned
            asyncio.run(call("attacker.test"))
    finally:
        server.shutdown()


def test_an_ipv4_mapped_address_is_judged_as_the_ipv4_address_on_every_supported_python() -> None:
    """Python 3.13 already does this inside is_global; 3.11 and 3.12 do not. A stand-in that reports every address as global proves the
    explicit unwrap, whatever interpreter runs the test."""
    import ipaddress

    from redhand_core.net.outbound import _is_public

    class OldInterpreterAddress(ipaddress.IPv6Address):
        @property
        def is_global(self) -> bool:
            return True

    assert _is_public(OldInterpreterAddress("::ffff:10.0.0.1")) is False
    assert _is_public(OldInterpreterAddress("::ffff:169.254.169.254")) is False
    assert _is_public(OldInterpreterAddress("::ffff:93.184.216.34")) is True
