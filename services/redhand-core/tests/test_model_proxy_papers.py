"""The model proxy decision papers (B5d) stay drafts: they exist, say they decide nothing, and never invent prices or compliance claims."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
PAPERS = {
    "docs/adr/0029-model-proxy-provider-key-custody.md": ["Draft", "not a decision"],
    "docs/launch/model-proxy-uptime-and-bypass.md": [
        "DRAFT",
        "not a decision",
        "removes RedHand from the path",
    ],
    "docs/launch/model-proxy-pdpa-position.md": [
        "DRAFT",
        "legal review",
        "makes no compliance claim",
    ],
    "docs/launch/model-proxy-cost-model.md": ["DRAFT", "Prices are blank on purpose"],
}


@pytest.mark.parametrize(("path", "markers"), PAPERS.items())
def test_each_paper_exists_and_says_it_is_a_draft(path: str, markers: list[str]) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    for marker in markers:
        assert marker in text, f"{path} must contain: {marker}"


def test_the_cost_model_has_no_filled_in_price() -> None:
    text = (ROOT / "docs/launch/model-proxy-cost-model.md").read_text(encoding="utf-8")
    inputs = text.split("## Inputs to fill in")[1].split("## Formula")[0]
    for line in inputs.splitlines():
        if line.startswith("|") and not line.startswith(("| Input", "|---")):
            assert line.rstrip().endswith("| |"), f"a value was filled in without the owner: {line}"


def test_the_papers_are_linked_from_the_launch_readme_and_the_adr() -> None:
    readme = (ROOT / "docs/launch/README.md").read_text(encoding="utf-8")
    adr = (ROOT / "docs/adr/0025-model-proxy-prototype.md").read_text(encoding="utf-8")
    for path in PAPERS:
        assert Path(path).name in readme + adr, path
