"""
The tuning and frozen split of the real documents (Phase 4 M4.7b, docs/security/m4-7b-split.md).

Take the first 120 names of REPOS in scripts/radar_real_life_proof.py, sort them by sha256 of the name, and the first 60 are the tuning set and
the other 60 the frozen set. Deterministic, so nobody can choose favourable repositories after seeing results. Names only: this module never
reads a document.

Usage (from the repository root): PYTHONPATH=. uv run python scripts/radar_real_documents_split.py   (prints the two lists)
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

PROOF_SCRIPT = Path(__file__).resolve().parent / "radar_real_life_proof.py"
CALLS = 120
TUNING_SIZE = 60


def repo_names() -> list[str]:
    """The first 120 names of REPOS, read from the proof script's source (not imported: it needs gateway credentials to run)."""
    tree = ast.parse(PROOF_SCRIPT.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "REPOS" for t in node.targets):
            if isinstance(node.value, ast.Tuple):
                return [ast.literal_eval(e) for e in node.value.elts][:CALLS]
    raise ValueError("REPOS not found in the proof script")


def split() -> tuple[list[str], list[str]]:
    """(tuning, frozen): names sorted by sha256, the first 60 and the last 60."""
    names = repo_names()
    if len(names) != CALLS or len(set(names)) != CALLS:
        raise ValueError("the proof script must list at least 120 distinct repositories")
    ranked = sorted(names, key=lambda n: hashlib.sha256(n.encode("utf-8")).hexdigest())
    return ranked[:TUNING_SIZE], ranked[TUNING_SIZE:]


if __name__ == "__main__":
    tuning, frozen = split()
    print("tuning:", *tuning, sep="\n  ")
    print("frozen:", *frozen, sep="\n  ")
