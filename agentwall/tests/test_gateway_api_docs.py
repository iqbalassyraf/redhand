"""The gateway serves no /docs, /redoc or /openapi.json in production (same rule as core). The app is built at import, so each case runs in a fresh interpreter."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROBE = "from agentwall.src.main import app; print(app.docs_url, app.redoc_url, app.openapi_url)"


@pytest.mark.parametrize(("environment", "expected"), [("production", "None None None"), ("staging", "/docs /redoc /openapi.json"), ("development", "/docs /redoc /openapi.json")])
def test_api_pages_follow_the_environment(environment: str, expected: str) -> None:
    env = {**os.environ, "AGENTWALL_ENVIRONMENT": environment}
    out = subprocess.run([sys.executable, "-c", PROBE], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60, check=True)
    assert out.stdout.strip().splitlines()[-1] == expected
