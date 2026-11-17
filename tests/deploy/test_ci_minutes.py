"""
CI spends GitHub Actions minutes only where a change needs them (owner request 2026-11-17, quota nearly used).

Two things must hold together: a change runs every job whose files it touched (an unknown path runs everything: fail closed), and the secret scan
runs on every change, docs included, because a secret can be pasted into a Markdown file. Jobs are skipped with `if:` (a skipped job reports success to
a required status check) instead of workflow-level `paths-ignore` (a workflow that never starts leaves a required check pending and blocks the merge).
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci_changes.py"
CI: dict[str, Any] = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
HEAVY = ("python", "sql", "dashboard")


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ci_changes", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci_changes = load()


def areas(*paths: str) -> set[str]:
    return set(ci_changes.areas_for(list(paths)))


# --- which jobs a change needs ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path",
    ["docs/handoff.md", "docs/plans/phase45-c1-sdk-keys.md", "docs/testing/results/2026-11-17-tonight.md", "docs/adr/0024-sdk-keys.md",
     "docs/briefing.md", "CHANGELOG.md", "README.md", "CLAUDE.md", ".ai-sync/state.json", ".github/dependabot.yml"],
)
def test_docs_and_notes_need_no_heavy_job(path: str) -> None:
    assert areas(path) == set()


@pytest.mark.parametrize(
    "path",
    ["docs/testing/briefs/2026-11-13-night-1.md", "docs/security/coverage-matrix.md", "docs/runbooks/destination-allowlist.md",
     "docs/api/redhand-core.openapi.json"],
)
def test_docs_that_python_tests_read_still_run_the_python_job(path: str) -> None:
    assert areas(path) == {"python"}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("agentwall/src/gateway.py", {"python"}),
        ("services/redhand-core/src/redhand_core/main.py", {"python"}),
        ("packages/redhand-sdk/src/redhand_sdk/client.py", {"python"}),
        ("tests/deploy/test_origins.py", {"python"}),
        ("deploy/cloudrun/smoke.sh", {"python"}),
        ("battleground/database/db.py", {"python"}),
        ("examples/langchain_agent.py", {"python"}),
        ("pyproject.toml", {"python"}),
        ("uv.lock", {"python"}),
        (".redhand-scan-baseline.json", {"python"}),
        # Python tests read SQL files (twin parity, the block gate) and dashboard sources (the night brief's on-screen strings), so these run python too.
        ("supabase/migrations/20261128000000_reported_only.sql", {"sql", "python"}),
        ("scripts/test_migrations.sh", {"python", "sql"}),
        ("apps/redhand-ui/src/app/page.tsx", {"dashboard", "python"}),
        ("apps/redhand-ui/package-lock.json", {"dashboard", "python"}),
    ],
)
def test_code_runs_the_jobs_that_check_it(path: str, expected: set[str]) -> None:
    assert areas(path) == expected


def test_a_change_to_the_workflow_or_the_classifier_runs_everything() -> None:
    assert areas(".github/workflows/ci.yml") == set(HEAVY)
    assert areas("scripts/ci_changes.py") == set(HEAVY)


@pytest.mark.parametrize("path", ["Dockerfile", "turbo.json", "package.json", "pnpm-workspace.yaml", ".dockerignore", ".gitignore", ".env.example", "new-dir/x.py"])
def test_an_unrecognised_path_runs_everything(path: str) -> None:
    assert areas(path) == set(HEAVY)


def test_areas_add_up_across_files() -> None:
    assert areas("docs/handoff.md", "supabase/tests/t.sql") == {"sql", "python"}
    assert areas("docs/handoff.md", "docs/runbooks/x.md") == {"python"}


def test_no_files_at_all_runs_everything() -> None:
    """An empty diff means the comparison could not be made (for example a missing base commit), not "nothing to check"."""
    assert areas() == set(HEAVY)


def test_the_script_prints_github_outputs_from_stdin() -> None:
    out = subprocess.run([sys.executable, str(SCRIPT)], input="supabase/tests/t.sql\ndocs/handoff.md\n", capture_output=True, text=True, check=True).stdout
    assert out.splitlines() == ["python=true", "sql=true", "dashboard=false"]


def test_the_script_runs_everything_when_told_to() -> None:
    out = subprocess.run([sys.executable, str(SCRIPT), "--all"], input="", capture_output=True, text=True, check=True).stdout
    assert out.splitlines() == ["python=true", "sql=true", "dashboard=true"]


# --- the workflow's shape --------------------------------------------------------------------------------------------------------------------

def triggers() -> dict[str, Any]:
    return CI.get("on") or CI[True]  # PyYAML reads the bare key `on` as the boolean True


def test_a_pull_request_commit_runs_ci_once_not_twice() -> None:
    on = triggers()
    assert on["push"] == {"branches": ["main"]}, "push on every branch doubles each PR commit with the pull_request run"
    assert on["pull_request"]["branches"] == ["main"]
    assert "workflow_dispatch" in on


def test_superseded_runs_are_cancelled() -> None:
    assert CI["concurrency"] == {"group": "${{ github.workflow }}-${{ github.ref }}", "cancel-in-progress": True}


def test_no_workflow_level_path_filter_that_could_leave_a_required_check_pending() -> None:
    for event in ("push", "pull_request"):
        assert not {"paths", "paths-ignore"} & set(triggers()[event])


def test_each_heavy_job_runs_only_when_its_area_changed() -> None:
    for job in HEAVY:
        spec = CI["jobs"][job]
        assert spec["needs"] == "changes"
        assert spec["if"] == f"needs.changes.outputs.{job} == 'true'"
    outputs = CI["jobs"]["changes"]["outputs"]
    assert set(outputs) == set(HEAVY)


def test_the_secret_scan_runs_on_every_change_and_cannot_be_skipped() -> None:
    job = CI["jobs"]["changes"]
    assert "if" not in job
    scan = [s for s in job["steps"] if "redhand scan" in str(s.get("run", ""))]
    assert len(scan) == 1 and "--strict" in scan[0]["run"] and "--baseline .redhand-scan-baseline.json" in scan[0]["run"]
    assert not scan[0].get("continue-on-error")
    assert not any("redhand scan" in str(s.get("run", "")) for s in CI["jobs"]["python"]["steps"]), "one scan, in the job that always runs"


def test_every_job_runs_on_linux() -> None:
    assert {spec["runs-on"] for spec in CI["jobs"].values()} == {"ubuntu-latest"}
