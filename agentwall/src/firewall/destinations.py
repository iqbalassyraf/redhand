"""
Destination extraction and matching (Phase 4 M7, docs/plans/phase4-m7-destination-allowlist.md): which web and email addresses did an agent
write into a tool call, and are they all on its allowed list?

Pure functions: no I/O, no DNS (a lookup on the hot path would be slow and, with DNS rebinding, unreliable). What this module can and
cannot see is the product truth the dashboard repeats:
- It reads what the agent WROTE in the call: URLs with a scheme (http, https, ftp, ftps, ws, wss, sftp) and email addresses. A destination
  written as a bare word (`evil.com`), encoded (base64), split across fields, or built by the tool itself is not found.
- Scheme, port, path and query are ignored: `http` and `https` to the same host are the same destination.
- Everything past the scan budget is NOT scanned, and `ScanResult.untracked` says so, so enforce mode can refuse what it could not check.

Parsers disagree about URLs (that is the attack: `http://good.com\\@evil.com` is evil.com to one parser and good.com to another), so one URL
yields a SET of candidate hosts, read the strict way and the browser way, before and after the first and the last `@`. A destination is
allowed only if EVERY candidate is on the list; a candidate that cannot be normalized is never allowed.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Any
import unicodedata
from urllib.parse import unquote_to_bytes

MAX_SCAN_CHARS = 64 * 1024  # the same budget as the honeytoken scan (gateway/honeytokens.py)
MAX_NODES = 1000
MAX_DEPTH = 16
MAX_DESTINATIONS = 50  # distinct destinations per call; more is "untracked"
MAX_URL_STARTS = 200  # scheme matches examined per call, so near-matches cost a bounded amount of work
MAX_RUN_CHARS = 2048  # an authority is never longer than a host (253) plus user info; longer is cut
MAX_OFFENDING = 5  # names reported for one call
MAX_COARSE_CHARS = 64

# A scheme in the browser's sense: `http:`, then two slashes, and browsers also accept backslashes (`http:\\evil.com`).
_SCHEME = re.compile(r"(?<![A-Za-z0-9+.\-])(?:https?|ftps?|wss?|sftp):[\\/]{2}", re.IGNORECASE)
# Characters that end an address in running text. Backslash, slashes, `?`, `#`, `@`, `:`, `[` and `]` are NOT here: they are part of the
# authority (or end it, which is decided below).
_RUN_END = re.compile(r"[\s\"'<>`^|{}(),;]")
# local part @ domain. The last label starts with a letter, so `pkg@1.2.3` (a version) is not an address; `\w` is Unicode-aware (IDN).
_EMAIL = re.compile(r"(?<![\w.%+\-])[\w.%+\-]{1,64}@((?:[\w\-]+\.)+[^\W\d_][\w\-]*|\[[0-9A-Fa-f:.]{2,45}\])")
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_NUMERIC_LABEL = re.compile(r"^(?:[0-9]+|0[xX][0-9a-fA-F]*)$")
_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})  # the label separators the IDNA codec also accepts


@dataclass(frozen=True, slots=True)
class Destination:
    """The candidate hosts of one address. None means a candidate that could not be normalized (never allowed)."""

    candidates: tuple[str | None, ...]


@dataclass(frozen=True, slots=True)
class ScanResult:
    destinations: tuple[Destination, ...]
    untracked: bool  # some text or structure was past the budget and was NOT scanned


# ---------------------------------------------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------------------------------------------

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


def coarse_host(host: str | None) -> str:
    """
    What a finding may keep of a destination: the last two labels of a name (a subdomain can carry the stolen data, so it is never stored),
    `ip-address` for an address and `unparseable` for a candidate that could not be normalized. Without a public-suffix list `a.b.example.co.uk`
    keeps `co.uk`: less than ideal, but never more than the registrable part.
    """
    if host is None:
        return "unparseable"
    if ":" in host or re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", host):
        return "ip-address"
    labels = host.split(".")
    return (host if len(labels) <= 2 else ".".join(labels[-2:]))[:MAX_COARSE_CHARS]


# ---------------------------------------------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------------------------------------------

def _strip_port(host: str) -> str:
    if host.startswith("["):
        end = host.find("]")
        if end != -1 and re.fullmatch(r":[0-9]*", host[end + 1:] or ":"):
            return host[: end + 1]
        return host  # something follows the bracket that is not a port: it will not normalize
    head, sep, tail = host.rpartition(":")
    return head if sep and (tail == "" or tail.isdigit()) else host


def _hosts_of(authority: str) -> list[str]:
    """The hosts one reading of an authority could mean. Parsers differ on which `@` ends the user info, so both are candidates."""
    if "@" not in authority:
        return [_strip_port(authority)]
    return [_strip_port(authority.rsplit("@", 1)[1]), _strip_port(authority.split("@", 1)[1])]


def _url_destination(text: str, start: int, slashes: str) -> Destination | None:
    chunk = text[start:start + MAX_RUN_CHARS]
    end = _RUN_END.search(chunk)
    run = chunk[: end.start()] if end else chunk
    while run and (run[-1] in ".:!?" or (run[-1] == "]" and run.count("[") < run.count("]"))):
        run = run[:-1]
    strict_end = min((i for i in (run.find("/"), run.find("?"), run.find("#")) if i != -1), default=len(run))
    browser_run = run.lstrip("/\\")  # a browser ignores extra slashes after the scheme (`http:///evil.com`)
    browser_end = min((i for i in (browser_run.find("/"), browser_run.find("?"), browser_run.find("#"), browser_run.find("\\")) if i != -1),
                      default=len(browser_run))
    readings = [run[:strict_end] if slashes == "//" else "", browser_run[:browser_end]]
    hosts = [h for authority in readings if authority for h in _hosts_of(authority)]
    if not hosts:
        return None  # `http://` with nothing after it is not a destination
    return Destination(tuple(dict.fromkeys(normalize_host(h) for h in hosts)))


def _text_destinations(text: str, starts_left: int) -> tuple[list[Destination], int, bool]:
    """The destinations in one string, how many scheme matches are still allowed, and whether the match budget ran out."""
    found: list[Destination] = []
    out_of_budget = False
    for match in _SCHEME.finditer(text):
        if starts_left <= 0:
            out_of_budget = True
            break
        starts_left -= 1
        destination = _url_destination(text, match.end(), match.group(0)[-2:])
        if destination is not None:
            found.append(destination)
    for email in _EMAIL.finditer(text):
        found.append(Destination((normalize_host(email.group(1)),)))
    return found, starts_left, out_of_budget


def scan_arguments(value: Any) -> ScanResult:
    """
    Every destination written in `value` (a tool call's arguments): string values and object keys, at any depth. Bounded work: at most
    MAX_SCAN_CHARS of text, MAX_NODES values, depth MAX_DEPTH, MAX_URL_STARTS scheme matches and MAX_DESTINATIONS distinct destinations;
    whatever lies past a bound is not scanned and `untracked` is True. Never raises.
    """
    seen: dict[tuple[str | None, ...], Destination] = {}
    untracked = False
    chars_left = MAX_SCAN_CHARS
    nodes_left = MAX_NODES
    starts_left = MAX_URL_STARTS
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack and not (untracked and len(seen) >= MAX_DESTINATIONS):
        node, depth = stack.pop()
        if nodes_left <= 0:
            untracked = True
            break
        nodes_left -= 1
        if isinstance(node, str):
            text = node
        elif isinstance(node, dict):
            if depth >= MAX_DEPTH:
                untracked = True
                continue
            for key, child in node.items():
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
            continue
        elif isinstance(node, (list, tuple)):
            if depth >= MAX_DEPTH:
                untracked = True
                continue
            stack.extend((child, depth + 1) for child in reversed(node))
            continue
        else:
            continue  # numbers, booleans, null: nothing to read
        if len(text) > chars_left:
            text, untracked = text[:chars_left], True
        chars_left -= len(text)
        found, starts_left, out_of_budget = _text_destinations(text, starts_left)
        untracked = untracked or out_of_budget
        for destination in found:
            if destination.candidates in seen:
                continue
            if len(seen) >= MAX_DESTINATIONS:
                untracked = True
                break
            seen[destination.candidates] = destination
    return ScanResult(destinations=tuple(seen.values()), untracked=untracked)


def disallowed(scan: ScanResult, allowed: frozenset[str]) -> tuple[str, ...]:
    """
    What is not on the list, as coarse names (`coarse_host`), without duplicates and at most MAX_OFFENDING. A destination is allowed only if
    every one of its candidate hosts is in `allowed` (entries must already be normalized with `normalize_host`); a candidate that could
    not be normalized is never allowed. An empty list therefore flags every destination.
    """
    offending: list[str] = []
    for destination in scan.destinations:
        for candidate in destination.candidates:
            if candidate is not None and candidate in allowed:
                continue
            name = coarse_host(candidate)
            if name not in offending:
                offending.append(name)
                if len(offending) >= MAX_OFFENDING:
                    return tuple(offending)
    return tuple(offending)
