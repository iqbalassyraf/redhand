"""The launch smoke script (scripts/smoke_launch.py) against the real app: it must pass on a staging-like core and FAIL on each exposure it is meant to catch."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from core_helpers import make_client

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "smoke_launch.py"
spec = importlib.util.spec_from_file_location("smoke_launch", SCRIPT)
assert spec and spec.loader
smoke = importlib.util.module_from_spec(spec)
sys.modules["smoke_launch"] = smoke
spec.loader.exec_module(smoke)

BASE = "http://testserver"
ORIGIN = "https://app.example.test"


def run(client: TestClient, **kwargs: Any) -> list[Any]:
    return smoke.check_core(client, BASE, allow_development=kwargs.pop("allow_development", True), dashboard_origin=kwargs.pop("dashboard_origin", None))


def failed(results: list[Any]) -> set[str]:
    return {r.name for r in results if not r.ok and not r.warn}


def test_a_development_core_passes_when_development_is_allowed() -> None:
    client, _ = make_client(ENVIRONMENT="development", CORS_ALLOWED_ORIGINS=[ORIGIN])
    # the dev login exists in development; everything else a stranger can reach must refuse
    assert failed(run(client, dashboard_origin=ORIGIN)) == set()


def test_development_mode_fails_the_check_when_it_is_not_allowed() -> None:
    client, _ = make_client(ENVIRONMENT="development")
    names = failed(run(client, allow_development=False))
    assert "core is not in development mode" in names and "the development login does not exist" in names


def test_a_wrong_cors_origin_fails_the_check() -> None:
    client, _ = make_client(ENVIRONMENT="development", CORS_ALLOWED_ORIGINS=["https://other.example.test"])
    assert "CORS allows the dashboard origin" in failed(run(client, dashboard_origin=ORIGIN))


def test_a_wildcard_cors_fails_the_check() -> None:
    client, _ = make_client(ENVIRONMENT="development", CORS_ALLOWED_ORIGINS=["*"])
    assert "CORS does not allow a foreign origin" in failed(run(client))


def test_the_report_exit_code_follows_failures_not_warnings() -> None:
    ok = smoke.Result("a", True)
    warn = smoke.Result("b", True, "x", warn=True)
    bad = smoke.Result("c", False, "status 200")
    lines: list[str] = []
    assert smoke.report([ok, warn], lines.append) == 0
    assert smoke.report([ok, bad], lines.append) == 1
    assert any(line.startswith("FAIL  c") for line in lines) and any(line.startswith("WARN  b") for line in lines)


@pytest.mark.parametrize("path", ["/v1/passports", "/v1/organizations"])
def test_a_route_that_stops_refusing_strangers_fails_the_check(path: str) -> None:
    client, _ = make_client(ENVIRONMENT="development")

    @client.app.get("/v1/passports-open")  # type: ignore[attr-defined]
    async def _open() -> dict[str, str]:
        return {"x": "y"}

    original = smoke.PROTECTED_GETS
    smoke.PROTECTED_GETS = ("/v1/passports-open",)
    try:
        assert "GET /v1/passports-open refuses a stranger" in failed(run(client))
    finally:
        smoke.PROTECTED_GETS = original
