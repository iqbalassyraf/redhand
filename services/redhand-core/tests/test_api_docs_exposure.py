"""Production serves no /docs, /redoc or /openapi.json (D1 follow-up from the launch smoke check); every other environment keeps them."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from redhand_core.config import Settings
from redhand_core.main import api_docs_urls, create_app

JWKS = {"OPERATOR_JWKS_URL": "https://project.supabase.example/auth/v1/.well-known/jwks.json", "OPERATOR_JWT_ISSUER": "https://project.supabase.example/auth/v1"}


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_production_serves_no_api_pages(path: str) -> None:
    client = TestClient(create_app(Settings(ENVIRONMENT="production", **JWKS)))  # type: ignore[arg-type]
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("environment", ["development", "staging", "test"])
def test_other_environments_keep_them(environment: str) -> None:
    assert api_docs_urls(environment) == {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}


def test_the_schema_is_still_generated_in_production() -> None:
    app = create_app(Settings(ENVIRONMENT="production", **JWKS))  # type: ignore[arg-type]
    assert "/v1/passports" in app.openapi()["paths"]
