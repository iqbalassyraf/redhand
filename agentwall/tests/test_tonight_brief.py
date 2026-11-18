"""
Tonight's brief (docs/testing/briefs/2026-11-18-tonight.md) finishes what the test day did not run. Its Part R and S rows are copied from the test-day brief,
so every promise the test-day brief makes for those parts must be here too; the new steps' exact words must be in the source that shows them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from test_test_day_brief import PROMISES

ROOT = Path(__file__).resolve().parents[2]
BRIEF = (ROOT / "docs" / "testing" / "briefs" / "2026-11-18-tonight.md").read_text(encoding="utf-8")

# Test-day promises for parts this brief does not repeat (T2 cold start, the leftovers N7, O8, P5, P8).
NOT_REPEATED = {
    "agentwall/src/gateway/service.py",
    "apps/redhand-ui/src/app/passports/[id]/timeline/page.tsx",
    "services/redhand-core/src/redhand_core/auth/operator.py",
    "apps/redhand-ui/src/lib/radarRules.ts",
    "apps/redhand-ui/src/app/radar/page.tsx",
}
CARRIED = [(text, path) for text, path in PROMISES if path not in NOT_REPEATED]

NEW = [
    ("Agent passport is reported only: an admin must promote it on the Passports page before it can use the gateway.", "services/redhand-core/src/redhand_core/routers/agent_auth.py"),
    ("Revoke this key? Anything still using it will be refused from the next batch. This cannot be undone.", "apps/redhand-ui/src/lib/sdkKeys.ts"),
    ("Verify chain", "apps/redhand-ui/src/app/blackbox/page.tsx"),
    ("chain intact.", "apps/redhand-ui/src/app/blackbox/page.tsx"),
    ("gateway keeps no audit ledger of its own", "deploy/cloudrun/smoke.sh"),
    ("gateway has no audit-ledger route", "scripts/smoke_launch.py"),
    (" revoked.", "apps/redhand-ui/src/app/passports/page.tsx"),
]


@pytest.mark.parametrize(("text", "path"), CARRIED + NEW)
def test_a_promised_string_is_in_the_brief_and_in_the_source(text: str, path: str) -> None:
    assert text in BRIEF, f"not in the brief: {text}"
    assert text in (ROOT / path).read_text(encoding="utf-8"), f"not in {path}: {text}"


def test_every_part_r_and_s_step_is_carried_over() -> None:
    for step in [f"R{i}" for i in range(1, 14)] + ["R15"] + [f"S{i}" for i in range(1, 12)]:
        assert f"| {step} |" in BRIEF, step


def test_part_0_deploys_the_newest_migration() -> None:
    newest = sorted(p.name for p in (ROOT / "supabase" / "migrations").glob("*.sql"))[-1]
    assert newest in BRIEF.split("## Part R")[0], f"Part 0 must apply {newest}"


@pytest.mark.parametrize(
    ("script", "options"),
    [("scripts/issue_signup_code.py", ["--note", "--days"]), ("scripts/smoke_launch.py", ["--core", "--gateway", "--dashboard-origin"])],
)
def test_the_commands_use_options_the_scripts_really_have(script: str, options: list[str]) -> None:
    source = (ROOT / script).read_text(encoding="utf-8")
    for option in options:
        assert f'"{option}"' in source, f"{script} has no {option}"
        assert re.search(rf"{Path(script).name}[^\n]*{re.escape(option)}", BRIEF), f"the brief does not use {option} with {script}"


def test_the_rules_are_stated_and_the_test_day_brief_points_here() -> None:
    assert "Never paste a key, token or secret into chat" in BRIEF and "NOT RUN is not PASS" in BRIEF
    assert "never on the main organization" in BRIEF
    old = (ROOT / "docs" / "testing" / "briefs" / "2026-11-18-test-day.md").read_text(encoding="utf-8")
    assert "2026-11-18-tonight.md" in old
