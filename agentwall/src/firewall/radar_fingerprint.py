"""
A fingerprint of the Radar rules (Phase 4 M4.6, docs/adr/0016-block-gate.md).

Measured results only count for the rules they were measured on. The fingerprint is a SHA-256 of the rules file, so any edit to it, even a
comment, makes earlier measurements stale. That is deliberately blunt: a change then has to be acknowledged by a person re-recording the
evidence, and the hash is the same on every Python version (an AST or token hash is not). It says nothing about WHAT changed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from . import radar

UNKNOWN = "unknown"
MODEL_SUFFIX = "+model"  # the helper model was trained on blind rounds 1 and 2, so measurements of the rules alone do not cover it


def fingerprint_of(data: bytes) -> str:
    """Line endings are normalised so a Windows checkout gives the same value."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()[:16]


def rules_fingerprint(*, model_enabled: bool = False) -> str:
    """The fingerprint of the rules this process runs, or "unknown" when the file cannot be read (never a guess)."""
    path = getattr(radar, "__file__", None)
    if not path:
        return UNKNOWN
    try:
        value = fingerprint_of(Path(path).read_bytes())
    except OSError:
        return UNKNOWN
    return value + MODEL_SUFFIX if model_enabled else value
