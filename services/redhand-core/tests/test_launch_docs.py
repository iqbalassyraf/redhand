"""The launch documents stay true to the code: every setting of core and the gateway is on the environment variable page."""

from __future__ import annotations

from pathlib import Path

from agentwall.config.settings import Settings as GatewaySettings
from redhand_core.config import Settings as CoreSettings

PAGE = (Path(__file__).resolve().parents[3] / "docs" / "launch" / "environment-variables.md").read_text(encoding="utf-8")


def test_every_core_setting_is_documented() -> None:
    missing = [name for name in CoreSettings.model_fields if f"`{name}`" not in PAGE]
    assert not missing, f"add these to docs/launch/environment-variables.md: {missing}"


def test_every_gateway_setting_is_documented() -> None:
    missing = [f"AGENTWALL_{name}" for name in GatewaySettings.model_fields if f"`AGENTWALL_{name}`" not in PAGE]
    assert not missing, f"add these to docs/launch/environment-variables.md: {missing}"


def test_the_page_holds_no_secret_value() -> None:
    for marker in ("eyJ", "-----BEGIN", "sk-", "rh_live_", "rh_inv_", "rh_join_"):
        assert marker not in PAGE


def test_the_owner_checklist_names_the_newest_migration() -> None:
    """The checklist tells the owner which migration is the newest to apply in production; it must never fall behind main."""
    root = Path(__file__).resolve().parents[3]
    newest = sorted(p.name for p in (root / "supabase" / "migrations").glob("*.sql"))[-1].removesuffix(".sql")
    checklist = (root / "docs" / "launch" / "owner-checklist.md").read_text(encoding="utf-8")
    assert f"`{newest}`" in checklist, f"docs/launch/owner-checklist.md must name the newest migration {newest}"


def test_the_production_hosting_decision_is_recorded_and_its_prices_are_left_to_the_owner() -> None:
    root = Path(__file__).resolve().parents[3]
    adr = (root / "docs" / "adr" / "0028-production-hosting.md").read_text(encoding="utf-8")
    assert "**Status:** Accepted by the owner, option A (2026-11-18)" in adr
    table = adr.split("| Item | Plan |")[1].split("Gateway work per call")[0]
    for line in table.splitlines():
        if line.startswith("| ") and not line.startswith("|---"):
            assert line.rstrip().endswith("| | | |"), f"a price was filled in without the owner: {line}"
