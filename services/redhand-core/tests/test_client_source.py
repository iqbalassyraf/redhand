"""
Which address a request came from (H3.3). Behind Cloud Run the socket peer is Google's front end, the same for every caller, so a per-address
limit needs the forwarded address. `X-Forwarded-For` is a list each proxy appends to, and the left part is whatever the caller wrote: only the
entries added by proxies we run behind can be trusted, counted from the right. uvicorn's `--forwarded-allow-ips '*'` takes the LEFTMOST entry,
which a caller can forge, so core reads the header itself.
"""

from __future__ import annotations

import pytest

from redhand_core.net.source import client_source


def scope(peer: str | None, forwarded: list[str] | None = None) -> dict[str, object]:
    headers = [(b"x-forwarded-for", value.encode()) for value in (forwarded or [])]
    return {"type": "http", "client": (peer, 1234) if peer else None, "headers": headers}


def test_with_no_trusted_proxy_the_header_is_ignored_completely() -> None:
    assert client_source(scope("10.1.1.1", ["203.0.113.7"]), trusted_hops=0) == "10.1.1.1"


def test_one_trusted_proxy_means_the_last_entry_is_the_caller() -> None:
    assert client_source(scope("35.1.1.1", ["198.51.100.1, 203.0.113.7"]), trusted_hops=1) == "203.0.113.7"


def test_a_forged_left_part_is_never_used() -> None:
    """The caller wrote `1.2.3.4`; the proxy appended the real address."""
    assert client_source(scope("35.1.1.1", ["1.2.3.4, 203.0.113.7"]), trusted_hops=1) == "203.0.113.7"
    assert client_source(scope("35.1.1.1", ["6.6.6.6", "1.2.3.4, 203.0.113.7"]), trusted_hops=1) == "203.0.113.7"  # two header lines


def test_two_trusted_proxies_count_from_the_right() -> None:
    assert client_source(scope("35.1.1.1", ["9.9.9.9, 203.0.113.7, 130.211.0.1"]), trusted_hops=2) == "203.0.113.7"


@pytest.mark.parametrize("forwarded", [[], [""], ["not-an-address"], ["203.0.113.7"]])
def test_fewer_usable_entries_than_hops_falls_back_to_the_peer(forwarded: list[str]) -> None:
    """Fail towards one shared bucket (over-limiting) rather than towards an attacker-chosen one (evasion)."""
    assert client_source(scope("35.1.1.1", forwarded), trusted_hops=2) == "35.1.1.1"


def test_an_unreadable_entry_falls_back_to_the_peer() -> None:
    assert client_source(scope("35.1.1.1", ["203.0.113.7, <script>"]), trusted_hops=1) == "35.1.1.1"


def test_ipv6_is_normalised_so_spelling_cannot_split_a_bucket() -> None:
    a = client_source(scope("35.1.1.1", ["2001:db8::1"]), trusted_hops=1)
    b = client_source(scope("35.1.1.1", ["2001:0db8:0000:0000:0000:0000:0000:0001"]), trusted_hops=1)
    assert a == b == "2001:db8::1"


def test_a_request_with_no_peer_gets_a_fixed_label_not_an_error() -> None:
    assert client_source(scope(None), trusted_hops=0) == "unknown"
