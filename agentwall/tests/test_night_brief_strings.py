"""
The night brief (docs/testing/briefs/2026-11-13-night-1.md) promises a tester the exact words the system will show. A tester who sees different words
cannot tell a bug from a stale brief, so every promised string must (1) be in the brief and (2) be in the source file that produces it. If wording
changes, this test fails until the brief is updated.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BRIEF = (ROOT / "docs" / "testing" / "briefs" / "2026-11-13-night-1.md").read_text(encoding="utf-8")

GATEWAY = "agentwall/src/gateway/service.py"
CORE_ALERTS = "services/redhand-core/src/redhand_core/radar/service.py"
RADAR_PAGE = "apps/redhand-ui/src/app/radar/page.tsx"
LOOP_FORM = "apps/redhand-ui/src/lib/loopForm.ts"
DEST_FORM = "apps/redhand-ui/src/lib/destinationForm.ts"
DEST_PANEL = "apps/redhand-ui/src/app/passports/DestinationsPanel.tsx"
RULES = "apps/redhand-ui/src/lib/radarRules.ts"

# (text in the brief, file that produces it). The text must appear verbatim in both.
PROMISES = [
    # gateway refusals and Black Box reasons
    ("PolicyViolation: this exact call was repeated too often (limit", GATEWAY),
    (
        "in {context.loop_window_seconds} seconds) and is paused for now.".replace(
            "{context.loop_window_seconds}", "{context.loop_window_seconds}"
        ),
        GATEWAY,
    ),
    (
        "PolicyViolation: this call contains an address that is not on this agent's allowed list.",
        GATEWAY,
    ),
    ("further repeats are paused for now.", GATEWAY),
    ("An address in this call is not on this agent's allowed list:", GATEWAY),
    # Telegram alerts
    ("more often than the loop limit allows.", CORE_ALERTS),
    (
        "Open the dashboard, Radar, Repeated calls. If throttling is on, the extra repeats were refused. Counts only: no call details are sent.",
        CORE_ALERTS,
    ),
    ("put an address outside its allowed list (", CORE_ALERTS),
    ("Recorded only: nothing was refused.", CORE_ALERTS),
    (
        "Open the dashboard, Passports, Allowed destinations. Only the last two parts of the address are shown: no call details are sent.",
        CORE_ALERTS,
    ),
    # loop card
    ("Repeated-call settings saved. They reach the gateway within a few seconds.", RADAR_PAGE),
    ("Tick the box to confirm this change.", RADAR_PAGE),
    ("Only an admin can change these.", RADAR_PAGE),
    (
        "Your role cannot see the Radar. Ask an owner or admin to give you the security operator role.",
        RADAR_PAGE,
    ),
    ("Exempt this agent from repeat checks", RADAR_PAGE),
    (
        "it also stops throttling this agent: use it for a tool that is meant to be called again and again, such as a status check.",
        RADAR_PAGE,
    ),
    ("Watch (record repeats)", LOOP_FORM),
    ("Throttle (also pause repeats)", LOOP_FORM),
    (
        "I understand: a call repeated more often than the limit will be refused until the time window passes.",
        LOOP_FORM,
    ),
    ("Counts identical tool calls (same tool, same arguments)", LOOP_FORM),
    ("Nothing about the call is stored: only the agent, the tool and how often.", LOOP_FORM),
    (
        "The agent sent the same tool call, with the same arguments, more often than the limit in a short time: it may be stuck in a loop.",
        RULES,
    ),
    # destination panel
    ("Allowed destinations for", DEST_PANEL),
    ("None. With the check on, every address in a call is outside the list.", DEST_PANEL),
    ("Allow a host", DEST_PANEL),
    ("Only an admin can change these.", DEST_PANEL),
    ("Host allowed.", DEST_PANEL),
    ("Saved. It reaches the gateway within a few seconds.", DEST_PANEL),
    (" removed.", DEST_PANEL),
    ("Watch (record addresses outside the list)", DEST_FORM),
    ("Enforce (also refuse the call)", DEST_FORM),
    ("Enter the host only, for example files.example.com: no http://, no path.", DEST_FORM),
    ("I understand: this lets the agent send data to this address.", DEST_PANEL),
    ("I understand: a call with an address that is not on this list will be refused.", DEST_FORM),
    (
        "I understand: while this is off, RedHand stops checking where this agent sends data.",
        DEST_FORM,
    ),
    ("This is the last allowed destination: switch to Watch or Off first.", DEST_FORM),
    (
        "written as a plain word, encoded, split across fields or built by the tool itself is not seen",
        DEST_FORM,
    ),
    ("Matches are exact: sub.example.com is not example.com.", DEST_FORM),
    (
        "The agent put a web or email address that is not on its allowed list into a call. Only the last two parts of the address are shown.",
        RULES,
    ),
    # tools
    ("ALL CHECKS PASSED", "deploy/cloudrun/smoke.sh"),
    ("ALL CHECKS PASSED", "scripts/staging_agent.py"),
    ("PASS: inside the budget", "scripts/latency_baseline.py"),
    ("OVER BUDGET", "scripts/latency_baseline.py"),
    ("calls_taking_1_5s_or_more_end_to_end", "scripts/latency_baseline.py"),
    ("first refusal at call:", "scripts/staging_agent.py"),
    ("--vary", "scripts/staging_agent.py"),
    ("This action requires the '", "services/redhand-core/src/redhand_core/auth/operator.py"),
    (
        "LOOP_DETECTION_ENABLED",
        "agentwall/config/settings.py",
    ),  # the AGENTWALL_ prefix is applied by the settings class (env_prefix)
    ("AGENTWALL_DESTINATION_CHECK_ENABLED", "docs/runbooks/destination-allowlist.md"),
]


@pytest.mark.parametrize(
    "text,path", PROMISES, ids=[f"{p.split('/')[-1]}: {t[:48]}" for t, p in PROMISES]
)
def test_a_promised_string_is_in_the_brief_and_in_the_source(text: str, path: str) -> None:
    needle = text.replace("{context.loop_window_seconds}", "")
    # A sentence the source wraps over several string literals ("..." + "...") is one sentence on the screen.
    source = re.sub(r'"\s*\+\s*\n\s*"', "", (ROOT / path).read_text(encoding="utf-8"))
    in_brief = text.split("{")[0] if "{" in text else text
    assert in_brief.strip() in BRIEF or text.strip() in BRIEF, f"not in the brief: {text}"
    assert needle.strip() in source or text.split("{")[0].strip() in source, (
        f"not in {path}: {text}"
    )


def test_the_kill_switch_names_in_the_brief_match_the_settings() -> None:
    settings = (ROOT / "agentwall" / "config" / "settings.py").read_text(encoding="utf-8")
    assert "LOOP_DETECTION_ENABLED" in settings and "DESTINATION_CHECK_ENABLED" in settings
    assert (
        "AGENTWALL_LOOP_DETECTION_ENABLED" in BRIEF
        and "AGENTWALL_DESTINATION_CHECK_ENABLED" in BRIEF
    )


def test_the_commands_in_the_brief_use_options_the_staging_agent_really_has() -> None:
    script = (ROOT / "scripts" / "staging_agent.py").read_text(encoding="utf-8")
    for option in ("--tool", "--args", "--times", "--delay", "--vary"):
        assert f'"{option}"' in script and option in BRIEF


def test_the_brief_never_asks_for_a_secret_to_be_pasted_into_chat() -> None:
    assert "Never paste a key, token or secret into chat" in BRIEF
    assert "NOT RUN is not PASS" in BRIEF and "Do **NOT** read shell history" in BRIEF
