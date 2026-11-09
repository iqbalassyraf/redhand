"""
Honeytoken values. A honeytoken must look like the real thing (so an attacker does not skip it) yet never be
valid anywhere, and must carry no RedHand marker. Values are random (secrets module), shown once, and only
their SHA-256 digest and last four characters are stored.
"""

from __future__ import annotations

import hashlib
import secrets
import string
from typing import Literal

HoneytokenKind = Literal["api_key", "aws_key", "password", "canary"]

_BASE62 = string.ascii_letters + string.digits
_UPPER_DIGITS = string.ascii_uppercase + string.digits


def _random(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_value(kind: HoneytokenKind) -> str:
    """api_key: sk_live_ + 32 base62 (128+ bits). aws_key: AKIA + 16 uppercase alphanumerics. password and canary:
    24 alphanumerics with at least one lowercase, uppercase and digit (alphanumeric so the gateway can find it in
    text without guessing delimiters). A canary deliberately has the same shape as a password and NO marker, so
    it needs no gateway change and an attacker cannot recognise it in a stolen prompt (docs/adr/0012-honeytokens.md).
    An unknown kind is an error, never a silent password."""
    if kind == "api_key":
        return "sk_live_" + _random(_BASE62, 32)
    if kind == "aws_key":
        return "AKIA" + _random(_UPPER_DIGITS, 16)
    if kind not in ("password", "canary"):
        raise ValueError(f"unknown honeytoken kind: {kind!r}")
    while True:
        value = _random(_BASE62, 24)
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value):
            return value


def digest_of(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hint_of(value: str) -> str:
    return value[-4:]
