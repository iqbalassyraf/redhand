"""
Black Box payload capture (Phase 3 M2b), the pure module: what is redacted, that redaction happens BEFORE
the cut, that nothing unscanned is ever copied, and that the result always fits core's limits.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from agentwall.src.gateway.capture import (
    MAX_DEPTH,
    MAX_EXCERPT_BYTES,
    MAX_NODES,
    MAX_SCAN_CHARS,
    SENSITIVE_KEY,
    TOO_DEEP,
    TOO_LARGE,
    TOO_MANY,
    UNSUPPORTED,
    build_excerpt,
    redact_text,
    redact_value,
)

VALID_CARD = "4111 1111 1111 1111"  # a published test number, Luhn-valid
INVALID_CARD = "4111 1111 1111 1112"


def captured(value: Any) -> str:
    return build_excerpt(value).text


# ---------------------------------------------------------------------------
# What is found
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret, kind",
    [
        ("sk-abcdefghijklmnopqrstuvwx", "API_KEY"),
        ("sk-ant-api03-abcdefghijklmnopqrstuvwx", "API_KEY"),
        ("AKIAIOSFODNN7EXAMPLE", "AWS_KEY"),
        ("ya29.a0AfH6SMBabcdefghijklmnop", "GCP_TOKEN"),
        ("AIzaSyA1234567890abcdefghijklmnopqrstuv", "GCP_KEY"),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "GITHUB_TOKEN"),
        ("xoxb-1234567890-abcdefghij", "SLACK_TOKEN"),
        ("sk_live_abcdefghijklmnop1234", "STRIPE_KEY"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop", "JWT"),
        ("Bearer abcdefghijklmnopqrstuvwxyz0123", "BEARER_TOKEN"),
    ],
)
def test_secrets_are_redacted(secret: str, kind: str) -> None:
    out, n = redact_text(f"before {secret} after")
    assert secret not in out and f"[REDACTED:{kind}]" in out and n == 1
    assert out.startswith("before ") and out.endswith(" after")


def test_a_private_key_is_redacted_whole_even_when_the_end_marker_is_missing() -> None:
    whole = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    cut_off = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
    assert redact_text(whole)[0] == "[REDACTED:PRIVATE_KEY]"
    assert "MIIEvQ" not in redact_text(cut_off)[0]


def test_email_addresses_are_redacted() -> None:
    out, n = redact_text("mail ali.bin-abu+tag@example.com.my now")
    assert "ali" not in out and "[REDACTED:EMAIL]" in out and n == 1


@pytest.mark.parametrize("nric", ["900101-14-5678", "900101145678", "851231-10-1234"])
def test_malaysian_nric_numbers_are_redacted(nric: str) -> None:
    out, _ = redact_text(f"IC {nric}.")
    assert nric not in out and "[REDACTED:NRIC]" in out


@pytest.mark.parametrize("not_nric", ["901301-14-5678", "900132-14-5678", "900101-00-5678", "202611051430"])
def test_twelve_digits_that_are_not_a_nric_are_kept(not_nric: str) -> None:
    assert redact_text(f"order {not_nric}")[0] == f"order {not_nric}"


def test_card_numbers_are_redacted_only_when_the_checksum_is_valid() -> None:
    assert "4111" not in redact_text(f"card {VALID_CARD} ok")[0]
    assert "[REDACTED:CARD_NUMBER]" in redact_text(f"card {VALID_CARD} ok")[0]
    assert "4111111111111111" not in redact_text("4111111111111111")[0]
    assert "4111-1111-1111-1111" not in redact_text("4111-1111-1111-1111")[0]
    assert redact_text(f"id {INVALID_CARD}")[0] == f"id {INVALID_CARD}"


@pytest.mark.parametrize(
    "phone",
    ["+60 12-345 6789", "+60123456789", "012-345 6789", "0123456789", "03-1234 5678", "+44 20 7946 0958", "+1 415 555 2671"],
)
def test_phone_numbers_are_redacted(phone: str) -> None:
    out, _ = redact_text(f"call {phone} please")
    assert phone not in out and "[REDACTED:PHONE]" in out


def test_ordinary_numbers_are_not_mistaken_for_phones() -> None:
    for text in ("total 1234.56", "version 3.2.1", "id 42", "2026-11-05", "port 8080", "year 2026"):
        assert redact_text(text)[0] == text


def test_a_card_number_is_not_half_redacted_as_a_phone_number() -> None:
    out, n = redact_text(f"pay {VALID_CARD}")
    assert out == "pay [REDACTED:CARD_NUMBER]" and n == 1


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_nested_values_are_redacted_wherever_they_are() -> None:
    value = {"user": {"contacts": [{"email": "a@b.com"}, {"note": "ring 012-345 6789"}]}, "ok": "fine", "n": 3}
    out = json.loads(captured(value))
    assert out["ok"] == "fine" and out["n"] == 3
    assert "a@b.com" not in json.dumps(out) and "012-345" not in json.dumps(out)


def test_keys_are_scanned_too() -> None:
    out = captured({"a@b.com": "x"})
    assert "a@b.com" not in out and "[REDACTED:EMAIL]" in out


def test_two_keys_that_redact_to_the_same_text_do_not_lose_a_value() -> None:
    out = json.loads(captured({"a@b.com": 1, "c@d.com": 2}))
    assert sorted(out.values()) == [1, 2]


def test_numbers_that_are_card_nric_or_phone_numbers_are_redacted() -> None:
    out = json.loads(captured({"card": 4111111111111111, "ic": 900101145678, "phone": 60123456789, "qty": 3}))
    assert out["card"] == "[REDACTED:CARD_NUMBER]"
    assert out["ic"] == "[REDACTED:NRIC]"
    assert out["phone"] == "[REDACTED:PHONE]"
    assert out["qty"] == 3


@pytest.mark.parametrize(
    "name", ["password", "Password", "db_password", "passwd", "secret", "client_secret", "token", "access_token",
             "api_key", "apiKey", "Authorization", "cookie", "credential", "private_key", "nric", "mykad", "ssn"],
)
def test_the_value_of_a_sensitive_field_is_blanked_whatever_it_looks_like(name: str) -> None:
    out = json.loads(captured({name: "hunter2", "other": "visible"}))
    assert out[name] == SENSITIVE_KEY and out["other"] == "visible"


@pytest.mark.parametrize("name", ["max_tokens", "passenger", "compass", "bypass_count", "description", "tokenizer_name_x"])
def test_field_names_that_only_contain_those_letters_are_kept(name: str) -> None:
    assert json.loads(captured({name: "visible"}))[name] == "visible"


def test_a_sensitive_field_hides_a_whole_nested_value() -> None:
    out = json.loads(captured({"credential": {"user": "u", "pw": "p"}}))
    assert out == {"credential": SENSITIVE_KEY}


def test_json_scalars_are_kept_and_other_types_are_never_copied() -> None:
    out = json.loads(captured({"b": True, "n": None, "f": 1.5, "obj": object(), "raw": b"bytes", "s": {1, 2}}))
    assert out["b"] is True and out["n"] is None and out["f"] == 1.5
    assert out["obj"] == UNSUPPORTED and out["raw"] == UNSUPPORTED and out["s"] == UNSUPPORTED


# ---------------------------------------------------------------------------
# Redact first, cut second
# ---------------------------------------------------------------------------


def test_a_secret_straddling_the_cut_is_redacted_not_split() -> None:
    secret = "sk-" + "A" * 40
    for pad in range(MAX_EXCERPT_BYTES - 60, MAX_EXCERPT_BYTES + 5):
        ex = build_excerpt({"pad": "x" * pad, "s": secret})
        assert "sk-A" not in ex.text and "AAAAAAAA" not in ex.text, pad  # not even a fragment of it


def test_pii_straddling_the_cut_is_redacted_not_split() -> None:
    for pad in range(MAX_EXCERPT_BYTES - 40, MAX_EXCERPT_BYTES + 5):
        ex = build_excerpt({"pad": "x" * pad, "e": "alice@example.com", "ic": "900101-14-5678", "c": VALID_CARD})
        for fragment in ("alice@", "900101", "4111 11"):
            assert fragment not in ex.text, (pad, fragment)


def test_output_is_cut_to_two_kilobytes_and_says_so() -> None:
    ex = build_excerpt({"data": "y" * 10_000})
    assert ex.truncated is True and len(ex.text.encode()) <= MAX_EXCERPT_BYTES and len(ex.text) <= MAX_EXCERPT_BYTES
    assert ex.original_bytes > MAX_EXCERPT_BYTES


def test_a_short_value_is_whole_and_not_marked_truncated() -> None:
    ex = build_excerpt({"path": "/tmp/a"})
    assert ex.text == '{"path":"/tmp/a"}' and ex.truncated is False and ex.original_bytes == len(ex.text)


def test_the_cut_never_splits_a_multibyte_character() -> None:
    ex = build_excerpt({"t": "例" * 5000})
    ex.text.encode("utf-8")  # raises if a character was split
    assert len(ex.text.encode()) <= MAX_EXCERPT_BYTES and ex.truncated


def test_the_result_always_fits_core_limits_even_for_hostile_input() -> None:
    hostile = ['"' * 5000, "\x00" * 5000, "\\" * 5000, "😀" * 3000, "a" * 100_000, ["x"] * 100_000, {"k" * 3000: 1}]
    for value in hostile:
        d = build_excerpt(value).as_dict()
        assert set(d) == {"text", "truncated", "original_bytes"}
        assert len(d["text"]) <= 2048 and isinstance(d["truncated"], bool) and d["original_bytes"] >= 0


# ---------------------------------------------------------------------------
# Never store what was not scanned
# ---------------------------------------------------------------------------


def test_text_past_the_scan_budget_is_replaced_not_copied() -> None:
    ex = build_excerpt({"first": "ok", "huge": "z" * (MAX_SCAN_CHARS + 1), "after": "also dropped"})
    out = json.loads(ex.text)
    assert out["first"] == "ok" and out["huge"] == TOO_LARGE
    # Once the budget is spent nothing else is copied, not even the later key or value.
    assert "also dropped" not in ex.text and "after" not in ex.text and "zzzz" not in ex.text


def test_a_secret_hidden_after_a_huge_value_is_never_copied() -> None:
    ex = build_excerpt(["a" * MAX_SCAN_CHARS, "sk-" + "B" * 40])
    assert "BBBB" not in ex.text


def test_too_many_values_are_replaced_by_a_marker() -> None:
    redacted, _ = redact_value(list(range(MAX_NODES + 50)))
    assert len(redacted) == MAX_NODES + 50
    assert redacted[0] == 0 and redacted[MAX_NODES - 5] == MAX_NODES - 5  # the first values are kept
    assert redacted[-1] == TOO_MANY  # everything past the limit is a marker, not a copy


def test_a_wide_object_is_bounded_too() -> None:
    redacted, _ = redact_value({f"k{i}": i for i in range(MAX_NODES + 50)})
    assert TOO_MANY in redacted.values()


def test_deep_nesting_is_cut_off_with_a_marker() -> None:
    value: Any = "leaf"
    for _ in range(MAX_DEPTH + 5):
        value = [value]
    ex = build_excerpt(value)
    assert TOO_DEEP in ex.text and "leaf" not in ex.text


def test_a_very_deep_value_does_not_crash_or_recurse_forever() -> None:
    value: Any = "leaf"
    for _ in range(5000):
        value = {"a": value}
    assert TOO_DEEP in build_excerpt(value).text


def test_redaction_is_fast_enough_for_the_hot_path() -> None:
    """Not a benchmark (those are in docs); a generous bound that still catches a pathological regex."""
    value = {"rows": [{"name": "n" * 20, "email": "a@b.com", "ic": "900101-14-5678", "note": "x" * 200} for _ in range(150)]}
    start = time.perf_counter()
    build_excerpt(value)
    assert time.perf_counter() - start < 1.0


def test_pathological_digit_and_separator_runs_do_not_blow_up() -> None:
    for text in ("1 " * 30_000, "1" * 60_000, "+" + "1 " * 20_000, "-" * 60_000, "-----BEGIN PRIVATE KEY-----" * 2000):
        start = time.perf_counter()
        build_excerpt(text)
        assert time.perf_counter() - start < 2.0, text[:12]


def test_the_shortest_possible_email_is_still_redacted_and_shorter_text_is_left_alone() -> None:
    """The scan skips text under 6 characters because no rule can match less than a@b.co."""
    assert redact_text("a@b.co")[0] == "[REDACTED:EMAIL]"
    assert redact_text("a@b.c") == ("a@b.c", 0)  # not an address (the last label needs two letters)
    assert redact_text("ab@c") == ("ab@c", 0)


def test_short_numbers_are_kept_and_long_ones_are_scanned() -> None:
    out = json.loads(captured({"qty": 1234567, "phone": 60123456789, "ratio": 0.25}))
    assert out["qty"] == 1234567 and out["ratio"] == 0.25 and out["phone"] == "[REDACTED:PHONE]"
