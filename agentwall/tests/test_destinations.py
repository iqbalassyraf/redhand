"""
Destination extraction and matching (Phase 4 M7, docs/plans/phase4-m7-destination-allowlist.md section 3.1 and 3.2): the web and email
addresses an agent wrote into a tool call, normalized so that look-alikes, number tricks and parser differences cannot slip past an
allowlist. Every bypass class in the plan has a case here. Pure functions, no I/O, no DNS.
"""

from __future__ import annotations

import json
from pathlib import Path
import random
import time
from typing import Any

import pytest

from agentwall.src.firewall.destinations import (
    MAX_DESTINATIONS,
    MAX_NODES,
    MAX_SCAN_CHARS,
    Destination,
    coarse_host,
    disallowed,
    normalize_host,
    scan_arguments,
)

VECTORS = json.loads((Path(__file__).parent / "data" / "destination_normalize_vectors.json").read_text())


def candidates(value: Any) -> list[tuple[str | None, ...]]:
    """The candidate-host tuples found in `value`, each sorted (None last) so a case does not depend on discovery order."""
    scan = scan_arguments(value)
    return [tuple(sorted(d.candidates, key=lambda c: (c is None, c or ""))) for d in scan.destinations]


# ---------------------------------------------------------------------------------------------------------------
# normalize_host: the shared vectors (the same file runs against core's copy in test_destination_normalizers_in_sync)
# ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("vector", VECTORS, ids=[f"{v['note']}: {v['input'][:30]!r}" for v in VECTORS])
def test_normalize_host_vectors(vector: dict[str, Any]) -> None:
    assert normalize_host(vector["input"]) == vector["expected"]


@pytest.mark.parametrize("vector", [v for v in VECTORS if v["expected"] is not None], ids=lambda v: v["note"])
def test_a_normalized_host_normalizes_to_itself(vector: dict[str, Any]) -> None:
    once = normalize_host(vector["input"])
    assert once is not None and normalize_host(once) == once


# ---------------------------------------------------------------------------------------------------------------
# URLs: one URL gives a SET of candidate hosts, and every candidate must be allowed
# ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text,expected",
    [
        ("https://good.com/path?q=1#frag", [("good.com",)]),
        ("HTTP://GOOD.COM.", [("good.com",)]),
        ("http://user:pass@good.com:8080/x", [("good.com",)]),
        ("http://good.com@evil.com/", [("evil.com",)]),  # the part before @ is user info, not the host
        ("http://evil.com#@good.com", [("evil.com",)]),  # a fragment is not part of the authority
        ("http://evil.com?@good.com", [("evil.com",)]),
        ("http://evil.com/@good.com", [("evil.com",)]),
        ("http://good.com\\@evil.com/", [("evil.com", "good.com")]),  # a browser stops at the backslash, a strict parser does not
        ("http://evil.com\\.good.com/", [("evil.com", None)]),
        ("http://good.com%40evil.com/", [(None,)]),  # an encoded @ is not a delimiter, and not a valid host either
        ("http://good.com%2f@evil.com/", [("evil.com",)]),
        ("http://[::1]:8080/x", [("::1",)]),
        ("http://[::ffff:7f00:1]/", [("127.0.0.1",)]),
        ("http://2130706433/", [("127.0.0.1",)]),
        ("http://0x7f.1/", [("127.0.0.1",)]),
        ("http://0177.0.0.1:9/", [("127.0.0.1",)]),
        ("http://аpple.com/", [("xn--pple-43d.com",)]),  # a Cyrillic letter makes a different name
        ("http://bücher.de/", [("xn--bcher-kva.de",)]),
        ("http://good.com.evil.com/", [("good.com.evil.com",)]),
        ("http://evilgood.com/", [("evilgood.com",)]),
        ("ftp://files.good.com/a", [("files.good.com",)]),
        ("ftps://files.good.com/a", [("files.good.com",)]),
        ("wss://sock.good.com/", [("sock.good.com",)]),
        ("sftp://h.good.com/", [("h.good.com",)]),
        ("see (https://good.com), then https://other.org.", [("good.com",), ("other.org",)]),
        ("go to https://good.com/?next=http://evil.com now", [("good.com",), ("evil.com",)]),  # a URL inside a URL is found too
        ("http://good.com http://good.com http://good.com", [("good.com",)]),  # repeats are one destination
        ("http://a@b@good.com/", [("good.com", None), ("good.com",)]),  # two @: parsers disagree which one ends the user info (the second entry is the email-looking part)
        ("Visit https://good.com! and https://other.org!!", [("good.com",), ("other.org",)]),  # punctuation after an address in prose
        ("is it https://good.com? or https://other.org:", [("good.com",), ("other.org",)]),
        ("use http:// or https:// for the link", []),  # a scheme with no host is not a destination
        ("http:///evil.com/x", [("evil.com",)]),  # a browser ignores extra slashes after the scheme
        ("http:\\\\evil.com/x", [("evil.com",)]),  # and accepts backslashes instead of slashes
        ("http:/\\evil.com/x", [("evil.com",)]),
        ("xhttp://evil.com and shttps://evil.org", []),  # not a scheme: a longer word
        ("http://exa mple.com/", [("exa",)]),  # the address ends at the space
    ],
)
def test_urls(text: str, expected: list[tuple[str | None, ...]]) -> None:
    assert sorted(candidates(text), key=repr) == sorted(expected, key=repr)


def test_a_url_with_two_at_signs_is_never_allowed() -> None:
    scan = scan_arguments("http://a@b@good.com/")
    assert disallowed(scan, frozenset({"good.com"})) == ("unparseable",)


def test_the_two_readings_of_a_backslash_url_must_both_be_allowed() -> None:
    scan = scan_arguments("http://good.com\\@evil.com/")
    assert disallowed(scan, frozenset({"good.com"})) == ("evil.com",)
    assert disallowed(scan, frozenset({"evil.com"})) == ("good.com",)
    assert disallowed(scan, frozenset({"good.com", "evil.com"})) == ()


# ---------------------------------------------------------------------------------------------------------------
# Email addresses
# ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text,expected",
    [
        ("alice@good.com", [("good.com",)]),
        ("mailto:alice@good.com", [("good.com",)]),
        ("Send to Bob.Smith+tag@Sub.Evil.co.uk please", [("sub.evil.co.uk",)]),
        ("a@b.com, c@d.org;e@f.net", [("b.com",), ("d.org",), ("f.net",)]),
        ("alice@аpple.com", [("xn--pple-43d.com",)]),
        ("alice@[::1]", [("::1",)]),
        ("pkg@1.2.3 and name@version", []),  # a version, and a host with no dot
        ("@decorator and user@", []),
        ("alice@good.com.", [("good.com",)]),
    ],
)
def test_email_addresses(text: str, expected: list[tuple[str | None, ...]]) -> None:
    assert sorted(candidates(text), key=repr) == sorted(expected, key=repr)


# ---------------------------------------------------------------------------------------------------------------
# Where the text can be: nested values, keys, other types
# ---------------------------------------------------------------------------------------------------------------

def test_nested_values_and_keys_are_scanned() -> None:
    value = {"a": {"b": ["x", {"c": "http://evil.com/x"}]}, "http://key.evil.org/": 1, "n": 5, "f": 2.5, "t": True, "z": None}
    assert sorted(candidates(value), key=repr) == [("evil.com",), ("key.evil.org",)]


def test_a_value_with_no_destination_has_none() -> None:
    assert candidates({"query": "invoices for March", "n": [1, 2, 3], "nested": {"a": "b"}}) == []
    assert scan_arguments({}).destinations == () and scan_arguments("").destinations == ()


# ---------------------------------------------------------------------------------------------------------------
# Matching and what a finding may keep
# ---------------------------------------------------------------------------------------------------------------

ALLOWED = frozenset({"good.com", "files.good.com", "127.0.0.1", "xn--bcher-kva.de"})


@pytest.mark.parametrize(
    "text,offending",
    [
        ("https://good.com/a", ()),
        ("https://files.good.com/a and alice@good.com", ()),
        ("https://evil.com/a", ("evil.com",)),
        ("https://sub.good.com/a", ("good.com",)),  # a subdomain is not the allowed host (no wildcards in v1)
        ("https://good.com.evil.com/", ("evil.com",)),
        ("https://evilgood.com/", ("evilgood.com",)),
        ("https://good.com@evil.com/", ("evil.com",)),
        ("http://good.com\\@evil.com/", ("evil.com",)),
        ("http://2130706433/", ()),  # the allowed address, written as one number
        ("http://0x7f.0.0.2/", ("ip-address",)),
        ("http://[::1]/", ("ip-address",)),
        ("https://bücher.de/", ()),  # the allowed name, written with its umlaut
        ("https://аpple.com/", ("xn--pple-43d.com",)),  # a look-alike letter makes a different name, which is not on the list
        ("http://good.com%40evil.com/", ("unparseable",)),
        ("ftp://evil.com and https://other.org and https://good.com", ("evil.com", "other.org")),
        ("alice@evil.com", ("evil.com",)),
        ("mailto:alice@good.com", ()),
    ],
)
def test_matching(text: str, offending: tuple[str, ...]) -> None:
    assert disallowed(scan_arguments(text), ALLOWED) == offending


def test_an_empty_allowlist_flags_every_destination() -> None:
    assert disallowed(scan_arguments("https://good.com/ and a@b.org"), frozenset()) == ("good.com", "b.org")


def test_what_a_finding_may_keep_is_the_last_two_labels_never_a_subdomain() -> None:
    assert coarse_host("secret-token-123.collector.evil.com") == "evil.com"
    assert coarse_host("evil.com") == "evil.com"
    assert coarse_host("a.b.evil.co.uk") == "co.uk"  # without a public-suffix list this keeps less than ideal, but never more
    assert coarse_host("localhost") == "localhost"
    assert coarse_host("203.0.113.7") == "ip-address" and coarse_host("2001:db8::1") == "ip-address"
    assert coarse_host(None) == "unparseable"
    assert len(coarse_host("x" * 80 + ".com")) <= 64


def test_the_offending_list_is_short_and_has_no_duplicates() -> None:
    text = " ".join(f"https://h{i}.evil.com/ https://h{i}.evil.com/" for i in range(30))
    assert disallowed(scan_arguments(text), frozenset()) == ("evil.com",)
    many = " ".join(f"https://host{i}.example{i}.org/" for i in range(30))
    assert len(disallowed(scan_arguments(many), frozenset())) <= 5


# ---------------------------------------------------------------------------------------------------------------
# Bounds: whatever is not looked at is reported, so enforce can refuse what it could not check
# ---------------------------------------------------------------------------------------------------------------

def test_more_than_the_limit_of_distinct_destinations_is_untracked() -> None:
    text = " ".join(f"https://h{i}.example.com/" for i in range(MAX_DESTINATIONS + 5))
    scan = scan_arguments(text)
    assert scan.untracked is True and len(scan.destinations) == MAX_DESTINATIONS
    assert scan_arguments(" ".join(f"https://h{i}.example.com/" for i in range(MAX_DESTINATIONS))).untracked is False


def test_more_matches_than_the_budget_is_untracked_even_when_they_are_all_the_same_address() -> None:
    flood = " ".join(["alice@good.com"] * 300)
    scan = scan_arguments(flood)
    assert scan.untracked is True and len(scan.destinations) == 1
    assert scan_arguments(" ".join(["alice@good.com"] * 50)).untracked is False
    assert scan_arguments(" ".join(["https://good.com/a"] * 300)).untracked is True


def test_text_beyond_the_character_budget_is_untracked() -> None:
    scan = scan_arguments("x " * (MAX_SCAN_CHARS // 2 + 10))
    assert scan.untracked is True
    assert scan_arguments("x" * 100).untracked is False


def test_too_many_values_or_too_deep_is_untracked() -> None:
    assert scan_arguments(["a"] * (MAX_NODES + 10)).untracked is True
    nested: Any = "http://evil.com/"
    for _ in range(40):
        nested = {"a": nested}
    assert scan_arguments(nested).untracked is True
    shallow: Any = "http://evil.com/"
    for _ in range(10):
        shallow = [shallow]
    scan = scan_arguments(shallow)
    assert scan.untracked is False and scan.destinations == (Destination(("evil.com",)),)


def test_a_destination_past_the_budget_is_never_silently_allowed() -> None:
    text = "x" * MAX_SCAN_CHARS + " https://evil.com/"
    scan = scan_arguments(text)
    assert scan.untracked is True  # the caller (enforce mode) refuses what it could not check


def test_untracked_is_false_for_ordinary_arguments() -> None:
    scan = scan_arguments({"url": "https://good.com/a", "note": "hello", "ids": list(range(20))})
    assert scan.untracked is False and len(scan.destinations) == 1


# ---------------------------------------------------------------------------------------------------------------
# Runtime: linear work, and nothing a caller sends can raise
# ---------------------------------------------------------------------------------------------------------------

def test_near_matches_and_a_mebibyte_are_scanned_inside_a_time_limit() -> None:
    worst = [
        "http://" * 9000,
        "http://a" * 7000,
        "http://" + "a@" * 30_000,
        "[" * 60_000,
        "@" * 60_000,
        "a" * 1_000_000,
        ("http://good.com\\" * 4000),
        "%" * 60_000,
        "0x" * 30_000,
        "a.b@c.de " * 7000,  # thousands of real addresses: normalizing each one used to cost ~30 ms
        "http://a " * 7000,
    ]
    started = time.perf_counter()
    for text in worst:
        scan_arguments({"x": text})
    assert time.perf_counter() - started < 3.0


def test_a_seeded_fuzz_never_raises_and_every_candidate_is_already_normal() -> None:
    rng = random.Random(7041)
    pieces = ["http://", "https://", "ftp://", "wss://", "@", "\\", "/", "?", "#", ".", "..", ":", "[", "]", "%", "%40", "%2f", "0x", "-", "_",
              "good.com", "evil.com", "1", "127", "255", "::1", "а", "ü", "．", "。", " ", "\n", "xn--", "a", "Z", "9", "\u0000"]
    started = time.perf_counter()
    for _ in range(3000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 40)))
        scan = scan_arguments({"k": text})
        for destination in scan.destinations:
            for candidate in destination.candidates:
                assert candidate is None or normalize_host(candidate) == candidate, (text, candidate)
        disallowed(scan, frozenset({"good.com"}))
    assert time.perf_counter() - started < 10.0
