"""
Core stores an allowlist entry with its own copy of `normalize_host`, because core must not import the gateway. The two must never differ:
a host stored one way and read from a call another way would be allowed when it should not be, or refused when it should be allowed.
Same approach as `test_sdk_secret_patterns_in_sync.py`: the same vectors through both, and the source text compared.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

import pytest

from agentwall.src.firewall.destinations import normalize_host as gateway_normalize
from redhand_core.destinations.hosts import normalize_host as core_normalize

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((Path(__file__).parent / "data" / "destination_normalize_vectors.json").read_text())


@pytest.mark.parametrize("vector", VECTORS, ids=[f"{v['note']}: {v['input'][:30]!r}" for v in VECTORS])
def test_both_normalizers_give_the_vector_answer(vector: dict[str, Any]) -> None:
    assert gateway_normalize(vector["input"]) == vector["expected"]
    assert core_normalize(vector["input"]) == vector["expected"]


def _normalizer_source(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.index("def normalize_host(raw: str)")
    end = text.find("def coarse_host(", start)
    return re.sub(r"\s+$", "", text[start:end] if end != -1 else text[start:])


def test_the_two_copies_have_identical_source() -> None:
    gateway = _normalizer_source(ROOT / "agentwall" / "src" / "firewall" / "destinations.py")
    core = _normalizer_source(ROOT / "services" / "redhand-core" / "src" / "redhand_core" / "destinations" / "hosts.py")
    assert gateway == core and "def _ipv6" in gateway  # a sanity check that the slice is not empty


def test_the_character_tables_are_identical_too() -> None:
    def tables(path: Path) -> list[str]:
        text = path.read_text(encoding="utf-8")
        return sorted(line for line in text.split("\n") if line.startswith(("_LABEL =", "_NUMERIC_LABEL =", "_DOTS =")))

    gateway = tables(ROOT / "agentwall" / "src" / "firewall" / "destinations.py")
    core = tables(ROOT / "services" / "redhand-core" / "src" / "redhand_core" / "destinations" / "hosts.py")
    assert gateway == core and len(gateway) == 3
