"""
The supply-chain checks stay in CI (H3.5, CLAUDE.md section 13): a locked-dependency audit for Python and for the dashboard that FAILS the job on a
known vulnerability, and weekly Dependabot updates. Dropping or softening one (continue-on-error) is the failure these tests catch.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI: dict[str, Any] = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
DEPENDABOT: dict[str, Any] = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))


def steps(job: str) -> list[dict[str, Any]]:
    return list(CI["jobs"][job]["steps"])


def test_the_python_job_audits_locked_dependencies_with_a_pinned_tool_and_cannot_be_skipped() -> None:
    audit = [s for s in steps("python") if "pip-audit" in str(s.get("run", ""))]
    assert len(audit) == 1
    assert "pip-audit@" in audit[0]["run"], "the audit tool itself must be pinned"
    assert "--frozen" in audit[0]["run"], "audit the locked versions, not whatever resolves today"
    assert not audit[0].get("continue-on-error")


def test_the_dashboard_job_fails_on_high_and_critical_advisories() -> None:
    # Production dependencies gate the build. Dev dependencies are audited too but informational only, while the picomatch advisory
    # (GHSA-fc5q-39xc-vjpf, no patched release, build tooling via tailwindcss 3) is accepted: see docs/release-readiness.md 3.2.
    audit = [s for s in steps("dashboard") if "npm audit" in str(s.get("run", ""))]
    gating = [s for s in audit if not s.get("continue-on-error")]
    assert len(gating) == 1, "exactly one npm audit step may fail the build"
    assert "--omit=dev" in gating[0]["run"] and "--audit-level=high" in gating[0]["run"]
    informational = [s for s in audit if s.get("continue-on-error")]
    assert all("--omit=dev" not in s["run"] for s in informational), "the informational step is the one that covers dev dependencies"


def test_dependabot_covers_python_the_dashboard_and_the_workflows_weekly_and_grouped() -> None:
    by_ecosystem = {u["package-ecosystem"]: u for u in DEPENDABOT["updates"]}
    assert set(by_ecosystem) == {"uv", "npm", "github-actions"}
    for update in by_ecosystem.values():
        assert update["schedule"]["interval"] == "weekly" and update["groups"]
    assert by_ecosystem["npm"]["directory"] == "/apps/redhand-ui"


def test_the_dashboard_forces_the_patched_postcss_inside_next() -> None:
    """next@15 pins postcss 8.4.31 (high severity advisories). The override points it at the top-level, patched postcss."""
    import json

    package = json.loads((ROOT / "apps" / "redhand-ui" / "package.json").read_text(encoding="utf-8"))
    assert package["overrides"] == {"next": {"postcss": "$postcss"}}
    lock = json.loads((ROOT / "apps" / "redhand-ui" / "package-lock.json").read_text(encoding="utf-8"))
    assert "node_modules/next/node_modules/postcss" not in lock["packages"]
