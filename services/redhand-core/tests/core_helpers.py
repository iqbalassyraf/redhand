"""Shared helpers for redhand-core tests: settings, clients and operator logins."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient
from pydantic import SecretStr

from redhand_core.auth.operator import issue_operator_token
from redhand_core.config import Settings, get_settings
from redhand_core.main import create_app
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.services.local_store import DEV_OPERATORS, LocalSupabaseAdapter

TEST_OPERATOR_SECRET = "test-operator-jwt-secret-0123456789abcdef0123456789abcdef"


def make_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "ENVIRONMENT": "test",
        "OPERATOR_JWT_SECRET": SecretStr(TEST_OPERATOR_SECRET),
    }
    base.update(overrides)
    environment = base.get("ENVIRONMENT", "test")
    if environment in ("development", "test"):
        return Settings(**base)
    # A shared environment cannot be configured with the HS256 test secret (H3.4), but these tests exercise what differs outside development
    # (signing key required, no dev login, no local store), not operator sign-in. Build the settings as "test", then switch the environment
    # without re-running the startup rules; those rules have their own tests.
    return Settings(**{**base, "ENVIRONMENT": "test"}).model_copy(update={"ENVIRONMENT": environment})


def make_client(store: Any | None = None, **settings_overrides: Any) -> tuple[TestClient, Settings]:
    """A client on a fresh local store (unless one is given) with test settings."""
    settings = make_settings(**settings_overrides)
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    active_store = store if store is not None else LocalSupabaseAdapter()
    app.dependency_overrides[get_supabase_service_client] = lambda: active_store
    return TestClient(app), settings


def operator_headers(
    user: str = "owner",
    settings: Settings | None = None,
    user_id: UUID | None = None,
    org: str | None = None,
) -> dict[str, str]:
    """Authorization header for one of the seeded dev operators (or an explicit user id)."""
    active = settings or make_settings()
    uid = user_id or UUID(DEV_OPERATORS[user]["id"])
    token = issue_operator_token(user_id=uid, email=None, settings=active)
    headers = {"Authorization": f"Bearer {token}"}
    if org:
        headers["X-RedHand-Org"] = org
    return headers
