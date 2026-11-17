"""
The test-day brief (docs/testing/briefs/2026-11-18-test-day.md) promises the tester exact words and gives exact commands. Every promised string must be in the brief and
in the source file that produces it, and every command must use options the script really has. If wording or options change, this test fails until the brief is updated.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BRIEF = (ROOT / "docs" / "testing" / "briefs" / "2026-11-18-test-day.md").read_text(encoding="utf-8")

ONBOARDING_UI = "apps/redhand-ui/src/lib/onboarding.ts"
ONBOARDING_CORE = "services/redhand-core/src/redhand_core/onboarding/service.py"
TEAM = "apps/redhand-ui/src/app/passports/TeamCard.tsx"
LIFECYCLE_UI = "apps/redhand-ui/src/lib/lifecycle.ts"

PROMISES = [
    # Part R: onboarding
    ("Almost there: open the link we e-mailed you to confirm the address, then sign in here.", "apps/redhand-ui/src/app/login/page.tsx"),
    ("Create your organization", ONBOARDING_UI),
    ("That sign-up code cannot be used. It may be wrong, already used or expired.", ONBOARDING_UI),
    ("That sign-up code cannot be used. It may be wrong, already used or expired.", ONBOARDING_CORE),
    ("Copy this link now. It will not be shown again: RedHand keeps only a hash.", ONBOARDING_UI),
    ("Create invite link", TEAM),
    ("Invites waiting", TEAM),
    ("Accept invite", "apps/redhand-ui/src/app/join/page.tsx"),
    ("Registering an agent issues its key, so it needs an admin. Ask one of your admins to register it.", "apps/redhand-ui/src/app/passports/page.tsx"),
    ("That invite cannot be used. It may be wrong, already used, revoked or expired.", ONBOARDING_UI),
    ("The last owner cannot be removed. Make someone else an owner first.", ONBOARDING_CORE),
    ("an owner? Owners can do everything, including removing you.", TEAM),
    # Part S: export and deletion
    ("Organization data", LIFECYCLE_UI),
    ("Export your data", LIFECYCLE_UI),
    ("Delete this organization", LIFECYCLE_UI),
    ("Download export", LIFECYCLE_UI),
    ("Export downloaded. Keep the file safe: it holds your organization's data.", LIFECYCLE_UI),
    ("This organization already exported its data in the last hour. Try again later.", "services/redhand-core/src/redhand_core/lifecycle/service.py"),
    ("Only an owner can export or delete this organization's data.", LIFECYCLE_UI),
    ("Request deletion of this organization? Every agent stops working now. You have 7 days to cancel.", LIFECYCLE_UI),
    ("This organization is scheduled for deletion on ", LIFECYCLE_UI),
    ("Export your data or cancel the deletion before then.", LIFECYCLE_UI),
    ("Cancel the deletion", LIFECYCLE_UI),
    ("Deletion cancelled. Agents stay frozen: unfreeze each one on Passports when you are ready, and create new SDK keys.", LIFECYCLE_UI),
    # Part T and Part 0
    ("Passport service unavailable; request denied.", "agentwall/src/gateway/service.py"),
    ("ALL CHECKS PASSED", "deploy/cloudrun/smoke.sh"),
    (" is publicly reachable", "scripts/smoke_launch.py"),
    ("core is served over https", "scripts/smoke_launch.py"),
    # leftovers
    ("Your role cannot see the incident view. Ask an owner or admin to give you the security operator role.", "apps/redhand-ui/src/app/passports/[id]/timeline/page.tsx"),
    ("This action requires the '", "services/redhand-core/src/redhand_core/auth/operator.py"),
    ("An agent's SDK reported a model that is not on the approved list.", "apps/redhand-ui/src/lib/radarRules.ts"),
    ("Model not on the approved list", "apps/redhand-ui/src/app/radar/page.tsx"),
]


@pytest.mark.parametrize(("text", "path"), PROMISES)
def test_a_promised_string_is_in_the_brief_and_in_the_source(text: str, path: str) -> None:
    assert text in BRIEF, f"not in the brief: {text}"
    assert text in (ROOT / path).read_text(encoding="utf-8"), f"not in {path}: {text}"


def test_the_role_refusal_names_the_admin_role() -> None:
    operator = (ROOT / "services/redhand-core/src/redhand_core/auth/operator.py").read_text(encoding="utf-8")
    assert "This action requires the '{minimum.name.lower()}' role or higher." in operator
    assert "This action requires the 'admin' role or higher." in BRIEF


@pytest.mark.parametrize(
    ("script", "options"),
    [("scripts/issue_signup_code.py", ["--note", "--days"]), ("scripts/smoke_launch.py", ["--core", "--gateway", "--dashboard-origin"])],
)
def test_the_commands_use_options_the_scripts_really_have(script: str, options: list[str]) -> None:
    source = (ROOT / script).read_text(encoding="utf-8")
    for option in options:
        assert f'"{option}"' in source, f"{script} has no {option}"
        assert re.search(rf"{Path(script).name}[^\n]*{re.escape(option)}", BRIEF), f"the brief does not use {option} with {script}"


def test_the_issue_code_command_reads_the_service_token_from_the_environment() -> None:
    source = (ROOT / "scripts/issue_signup_code.py").read_text(encoding="utf-8")
    assert "RH_SERVICE_TOKEN" in source and "RH_CORE_URL" in source
    assert "read -s RH_SERVICE_TOKEN" in BRIEF and "export RH_CORE_URL=" in BRIEF


def test_the_migrations_named_in_part_0_exist_in_order() -> None:
    named = re.findall(r"`(\d{14}_[a-z_]+\.sql)`", BRIEF.split("## Part Q")[0])
    assert named == sorted(named) and len(named) == 4
    for name in named:
        assert (ROOT / "supabase" / "migrations" / name).exists(), name
    newest = sorted(p.name for p in (ROOT / "supabase" / "migrations").glob("*.sql"))[-1]
    assert named[-1] == newest, "Part 0 must deploy up to the newest migration"


def test_the_rules_are_stated() -> None:
    assert "Never paste a key, token or secret into chat" in BRIEF
    assert "NOT RUN is not PASS" in BRIEF and "Do **NOT** read shell history" in BRIEF
    assert "never on the main organization" in BRIEF
