"""
Host normalization for an agent's allowed destinations (Phase 4 M7, docs/plans/phase4-m7-destination-allowlist.md).

An allowlist entry is stored in the one canonical spelling the gateway uses when it reads a call, so a stored host and a host found in a call can
never be spelled differently: `Example.COM.` and `example.com` are one host; `b\u00fccher.de` is stored as `xn--bcher-kva.de`; `0x7f.1` is `127.0.0.1`.

THIS FUNCTION IS A COPY of `normalize_host` in `agentwall/src/firewall/destinations.py`: core must not import the gateway (they are separate
services). `agentwall/tests/test_destination_normalizers_in_sync.py` runs the same vector file through both and fails if their source text differs,
so a change to one without the other cannot pass CI.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import unquote_to_bytes

_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_NUMERIC_LABEL = re.compile(r"^(?:[0-9]+|0[xX][0-9a-fA-F]*)$")
_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})  # the label separators the IDNA codec also accepts


def normalize_host(raw: str) -> str | None:
    """
    The one canonical spelling of a host, or None when it is not a valid host. A name is lower case, without trailing dots, percent-decoded
    once, NFKC-normalized and in IDNA (punycode) form, so a look-alike letter makes a DIFFERENT name. An IPv4 address in any form a browser
    accepts (one decimal number, hex, octal, two or three parts) is dotted decimal; IPv6 is compressed lower case, and an IPv4-mapped one is
    the IPv4 address. Ports, schemes and paths are not part of a host and make it invalid here.
    """
    try:
        return _normalize(raw)
    except ValueError:  # includes UnicodeError and ipaddress's errors
        return None


def _normalize(raw: str) -> str | None:
    host = raw.strip()
    if not host or len(host) > 2048:
        return None
    if host.startswith("["):
        if not host.endswith("]") or len(host) < 3:
            return None
        return _ipv6(host[1:-1])
    if ":" in host:
        return _ipv6(host)  # a bare IPv6 address (an allowlist entry); any other colon is invalid and fails there
    decoded = unquote_to_bytes(host).decode("utf-8")  # once: %2565 stays %65 and is refused below
    decoded = unicodedata.normalize("NFKC", decoded).translate(_DOTS).lower().rstrip(".")
    if not decoded:
        return None
    labels = decoded.split(".")
    if any(label == "" for label in labels):
        return None
    if _NUMERIC_LABEL.match(labels[-1]):
        return _ipv4(labels)  # a host that ends in a number MUST be an IPv4 address, as in a browser
    ascii_host = decoded.encode("idna").decode("ascii").lower()
    if len(ascii_host) > 253:
        return None
    if not all(_LABEL.match(label) for label in ascii_host.split(".")):
        return None
    return ascii_host


def _ipv4(labels: list[str]) -> str | None:
    if len(labels) > 4:
        return None
    numbers: list[int] = []
    for part in labels:
        value = _ipv4_part(part)
        if value is None:
            return None
        numbers.append(value)
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        return None
    total = numbers[-1] + sum(n * 256 ** (3 - i) for i, n in enumerate(numbers[:-1]))
    return ".".join(str((total >> shift) & 255) for shift in (24, 16, 8, 0))


def _ipv4_part(part: str) -> int | None:
    if part.lower().startswith("0x"):
        digits = part[2:]
        return int(digits, 16) if digits else 0
    if len(part) > 1 and part.startswith("0"):
        return int(part, 8) if re.fullmatch(r"[0-7]+", part) else None  # 08 is not octal
    return int(part, 10) if part.isdecimal() and part.isascii() else None


def _ipv6(text: str) -> str | None:
    if "%" in text or "/" in text:  # a zone id or a prefix is not a host
        return None
    address = ipaddress.IPv6Address(text)
    return str(address.ipv4_mapped) if address.ipv4_mapped is not None else str(address)
