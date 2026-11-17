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
