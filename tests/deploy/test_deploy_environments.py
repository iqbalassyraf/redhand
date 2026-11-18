"""
deploy/cloudrun/deploy.sh for staging and production (ADR 0028, option A). gcloud is replaced by a stub that records its arguments
(the same stub as test_origins.py); no cloud is touched. Production must be a deliberate act: its own service and secret names, at
least one warm instance, ENVIRONMENT=production, and a typed confirmation of the project before any change.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from test_origins import ROOT, _stub_gcloud

ORIGIN = "https://redhand.archtificial.com"


def _run(tmp_path: Path, command: str, **extra: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bin_dir, log = _stub_gcloud(tmp_path)
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path), "YES": "1",
        "SUPABASE_URL": "https://abcdefgh.supabase.co", "DASHBOARD_ORIGIN": ORIGIN, "TAG": "test", **extra,
    }
    result = subprocess.run(["bash", "deploy/cloudrun/deploy.sh", command], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    return result, (log.read_text().splitlines() if log.exists() else [])


def _deploys(calls: list[str]) -> list[str]:
    return [c for c in calls if c.startswith("run deploy ")]


PROD = {"DEPLOY_ENV": "production", "PROJECT_ID": "redhand-prod", "CONFIRM_PROJECT": "redhand-prod"}


def test_staging_is_unchanged_by_default(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "core")
    assert result.returncode == 0, result.stderr
    [deploy] = _deploys(calls)
    assert deploy.startswith("run deploy redhand-core ") and "--min-instances 0" in deploy and "ENVIRONMENT=staging@" in deploy
    assert "redhand-core-sa@" in deploy and "redhand-supabase-secret-key:latest" in deploy


def test_production_core_has_its_own_names_a_warm_instance_and_the_production_environment(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "core", **PROD)
    assert result.returncode == 0, result.stderr
    [deploy] = _deploys(calls)
    assert deploy.startswith("run deploy redhand-core-prod ") and "--project redhand-prod" in deploy
    assert "--min-instances 1" in deploy and "ENVIRONMENT=production@" in deploy and "ENVIRONMENT=staging" not in deploy
    assert "redhand-core-prod-sa@redhand-prod" in deploy and "redhand-supabase-secret-key-prod:latest" in deploy


def test_production_gateway_runs_in_production_and_never_turns_the_model_proxy_on(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "gateway", **PROD)
    assert result.returncode == 0, result.stderr
    [deploy] = _deploys(calls)
    assert deploy.startswith("run deploy redhand-gateway-prod ") and "--min-instances 1" in deploy
    assert "AGENTWALL_ENVIRONMENT=production@" in deploy and "MODEL_PROXY" not in deploy  # no-go for launch (ADR 0025)
    assert "redhand-internal-service-token-prod:latest" in deploy
    assert any(c.startswith("run services describe redhand-core-prod ") for c in calls)  # finds ITS core, not staging's


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"DEPLOY_ENV": "production", "PROJECT_ID": "redhand-prod"}, "CONFIRM_PROJECT"),
        ({"DEPLOY_ENV": "production", "PROJECT_ID": "redhand-prod", "CONFIRM_PROJECT": "redhand-staging"}, "CONFIRM_PROJECT"),
        ({"DEPLOY_ENV": "production", "CONFIRM_PROJECT": "test-project"}, "PROJECT_ID"),  # never gcloud's default project
        ({"DEPLOY_ENV": "prod"}, "DEPLOY_ENV"),
    ],
)
def test_production_needs_an_explicit_confirmed_project_and_a_known_environment(tmp_path: Path, extra: dict[str, str], message: str) -> None:
    result, calls = _run(tmp_path, "all", **extra)
    assert result.returncode != 0 and message in result.stderr
    assert not _deploys(calls) and not any(c.startswith(("secrets ", "services enable", "builds")) for c in calls)
