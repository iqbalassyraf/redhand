"""The Clerk brief (docs/testing/briefs/2026-11-19-clerk.md) quotes on-screen texts and names the settings the code reads: both must stay true."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BRIEF = (ROOT / "docs" / "testing" / "briefs" / "2026-11-19-clerk.md").read_text(encoding="utf-8")

PROMISES = [
    ("Create your organization", "apps/redhand-ui/src/lib/onboarding.ts"),
    ("That sign-up code cannot be used. It may be wrong, already used or expired.", "apps/redhand-ui/src/lib/onboarding.ts"),
    ("Copy this link now. It will not be shown again: RedHand keeps only a hash.", "apps/redhand-ui/src/lib/onboarding.ts"),
    ("Accept invite", "apps/redhand-ui/src/app/join/page.tsx"),
    ("Create an account", "apps/redhand-ui/src/components/clerk/ClerkLogin.tsx"),
    ("Sign out", "apps/redhand-ui/src/components/shell/AppShell.tsx"),
    ("OPERATOR_AUTH_PROVIDER", "services/redhand-core/src/redhand_core/config.py"),
    ("CLERK_ISSUER", "services/redhand-core/src/redhand_core/config.py"),
    ("NEXT_PUBLIC_AUTH_PROVIDER", "apps/redhand-ui/src/lib/auth.tsx"),
    ('template: "redhand"', "apps/redhand-ui/src/components/clerk/ClerkAuthProvider.tsx"),
]


@pytest.mark.parametrize(("text", "path"), PROMISES)
def test_a_promised_string_is_in_the_brief_and_in_the_source(text: str, path: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    if text == 'template: "redhand"':  # the brief writes it as a console snippet, the source as a constant
        assert 'getToken({template: "redhand"})' in BRIEF and 'CLERK_TOKEN_TEMPLATE = "redhand"' in source
        return
    assert text in BRIEF, f"not in the brief: {text}"
    assert text in source, f"not in {path}: {text}"


def test_the_template_claims_and_runbook_agree() -> None:
    runbook = (ROOT / "docs" / "runbooks" / "clerk-auth.md").read_text(encoding="utf-8")
    assert "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY" in runbook and "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY" in (ROOT / "apps/redhand-ui/src/components/clerk/ClerkAuthProvider.tsx").read_text(encoding="utf-8")
    for claim in ('"aud": "redhand-core"', "email_verified"):
        assert claim in runbook
    assert "redhand-core" in (ROOT / "services/redhand-core/src/redhand_core/config.py").read_text(encoding="utf-8")


def test_the_rules_are_stated() -> None:
    assert "Never paste a key, token or secret into chat" in BRIEF and "NOT RUN is not PASS" in BRIEF
    assert "Nothing in Clerk mode has run against a real Clerk instance" in BRIEF
