"""
The address a request came from, for per-address rate limits (CLAUDE.md sections 5.3 and 5.6).

Behind a proxy (Cloud Run) the socket peer is the proxy, the same for every caller. `X-Forwarded-For` is a list each proxy appends to, so only
the entries added by the proxies core runs behind can be trusted, counted from the right; everything to the left is whatever the caller wrote.
`trusted_hops` is how many proxies core sits behind (0 = none: the header is ignored). uvicorn's `--forwarded-allow-ips '*'` would take the
leftmost entry, which a caller can forge, so core does not use it.

Anything that cannot be read (too few entries, not an address) falls back to the socket peer: one shared bucket, which over-limits, never a
bucket the caller chose, which would let a caller step round the limit.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any


def _address(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return None


def client_source(scope: Mapping[str, Any], trusted_hops: int) -> str:
    client = scope.get("client")
    peer = str(client[0]) if client else "unknown"
    if trusted_hops <= 0:
        return peer
    entries: list[str] = []
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            entries.extend(part for part in value.decode("latin1").split(","))
    if len(entries) < trusted_hops:
        return peer
    chosen = _address(entries[-trusted_hops])
    return chosen or peer
