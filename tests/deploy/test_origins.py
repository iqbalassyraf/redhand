"""
deploy/cloudrun origin allow-list: the browser CORS list that deploy.sh writes to core and the gateway.

The list is credentialed, so the tests are mostly abuse cases: nothing but bare https origins may get through, and
deploy.sh must refuse a bad origin before it makes a single gcloud call. gcloud is replaced by a stub that records
its arguments; no real cloud is touched.
"""

from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BOTH = "https://redhand.archtificial.com,https://redhand-dashboard.vercel.app"


def _cors_json(raw: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", '. deploy/cloudrun/origins.sh; dashboard_cors_json "$1"', "_", raw],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )


def test_several_origins_are_kept_in_order_after_localhost() -> None:
    result = _cors_json(BOTH)
    assert result.returncode == 0
    assert json.loads(result.stdout) == [
        "http://localhost:3000", "https://redhand.archtificial.com", "https://redhand-dashboard.vercel.app",
    ]


def test_empty_gives_localhost_only() -> None:
    assert json.loads(_cors_json("").stdout) == ["http://localhost:3000"]


def test_whitespace_case_trailing_slash_and_duplicates_are_cleaned() -> None:
    result = _cors_json(" https://A.Example.com/ , https://a.example.com,http://localhost:3000 ")
    assert json.loads(result.stdout) == ["http://localhost:3000", "https://a.example.com"]


@pytest.mark.parametrize(
    "bad",
    [
        "*",
        "https://*.example.com",
        "https://example.com/path",
        "https://example.com?x=1",
        "http://example.com",
        "https://user@example.com",
        "https://example.com:99999999",
        'https://example.com","http://evil.example.com',
        "https://example.com\nhttps://evil.example.com",
        "https://localhost",
        "https://example",
        "https://-bad.example.com",
        "null",
        "https://a.example.com,,https://b.example.com",
        "https://a.example.com,*",
    ],
)
def test_anything_but_a_bare_https_origin_is_refused(bad: str) -> None:
    result = _cors_json(bad)
    assert result.returncode != 0
    assert result.stdout == ""  # no partial list a caller could use
    assert "not an allowed dashboard origin" in result.stderr


def test_more_than_five_origins_are_refused() -> None:
    many = ",".join(f"https://app{i}.example.com" for i in range(6))
    result = _cors_json(many)
    assert result.returncode != 0 and "more than 5" in result.stderr


def _stub_gcloud(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "gcloud.log"
    stub = tmp_path / "bin" / "gcloud"
    stub.parent.mkdir()
    stub.write_text(
        '#!/usr/bin/env bash\n'
        f'echo "$@" >> "{log}"\n'
        'case "$*" in\n'
        '  "config get-value project") echo test-project;;\n'
        '  "auth list"*) echo tester@example.com;;\n'
        'esac\n'
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    (stub.parent / "openssl").write_text("#!/usr/bin/env bash\n")
    (stub.parent / "openssl").chmod(0o755)
    return stub.parent, log


def _deploy(tmp_path: Path, command: str, origin: str) -> tuple[subprocess.CompletedProcess[str], str]:
    bin_dir, log = _stub_gcloud(tmp_path)
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path), "YES": "1",
        "SUPABASE_URL": "https://abcdefgh.supabase.co", "DASHBOARD_ORIGIN": origin,
    }
    result = subprocess.run(
        ["bash", "deploy/cloudrun/deploy.sh", command], cwd=ROOT, env=env, capture_output=True, text=True, check=False
    )
    return result, log.read_text() if log.exists() else ""


def test_deploy_cors_writes_every_origin_to_both_services(tmp_path: Path) -> None:
    result, calls = _deploy(tmp_path, "cors", BOTH)
    assert result.returncode == 0, result.stderr
    updates = [line for line in calls.splitlines() if line.startswith("run services update")]
    assert len(updates) == 2
    assert "CORS_ALLOWED_ORIGINS=" in updates[0] and "AGENTWALL_CORS_ALLOWED_ORIGINS=" in updates[1]
    for line in updates:
        assert "https://redhand.archtificial.com" in line and "https://redhand-dashboard.vercel.app" in line


@pytest.mark.parametrize("bad", ["*", "https://example.com/x", "http://example.com", f"{BOTH},*"])
def test_deploy_refuses_a_bad_origin_before_any_cloud_change(tmp_path: Path, bad: str) -> None:
    result, calls = _deploy(tmp_path, "cors", bad)
    assert result.returncode != 0
    assert "not an allowed dashboard origin" in result.stderr
    assert "run services" not in calls and "deploy" not in calls
