"""
What the gateway records about a tool call's arguments: their names and a digest, never the values (CLAUDE.md section 10).
The digest lets an owner correlate a Black Box row with a payload the customer holds without RedHand retaining it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def digest_arguments(arguments: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON form of the arguments (non-JSON values via str())."""
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def argument_keys(arguments: dict[str, Any]) -> list[str]:
    """The argument names, sorted, as text."""
    return sorted(str(k) for k in arguments)
