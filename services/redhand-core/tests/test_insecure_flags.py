"""
The development-only switches cannot be on in a shared environment (H2.5). A forgotten ALLOW_INSECURE_* variable on staging or production
would turn off the checks that stop an internal address being called (SSRF), so core refuses to start rather than run that way.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from redhand_core.config import Settings

JWKS = "https://example.supabase.co/auth/v1/.well-known/jwks.json"
ISSUER = "https://example.supabase.co/auth/v1"


def shared(environment: str, **flags: bool) -> Settings:
    return Settings(ENVIRONMENT=environment, OPERATOR_JWKS_URL=JWKS, OPERATOR_JWT_ISSUER=ISSUER, **flags)  # type: ignore[arg-type]


@pytest.mark.parametrize("environment", ["staging", "production"])
@pytest.mark.parametrize("flag", ["ALLOW_INSECURE_MCP_URLS", "ALLOW_INSECURE_WEBHOOK_URLS"])
def test_a_shared_environment_refuses_to_start_with_an_insecure_flag(environment: str, flag: str) -> None:
    with pytest.raises(ValidationError) as caught:
        shared(environment, **{flag: True})
    assert flag in str(caught.value)


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_a_shared_environment_without_the_flags_starts(environment: str) -> None:
    settings = shared(environment)
    assert not settings.ALLOW_INSECURE_MCP_URLS and not settings.ALLOW_INSECURE_WEBHOOK_URLS


@pytest.mark.parametrize("environment", ["development", "test"])
def test_development_and_test_may_use_the_flags(environment: str) -> None:
    settings = Settings(
        ENVIRONMENT=environment, OPERATOR_JWT_SECRET=SecretStr("s" * 40),
        ALLOW_INSECURE_MCP_URLS=True, ALLOW_INSECURE_WEBHOOK_URLS=True,  # type: ignore[arg-type]
    )
    assert settings.ALLOW_INSECURE_MCP_URLS and settings.ALLOW_INSECURE_WEBHOOK_URLS


def test_the_refusal_names_the_flag_and_never_a_value() -> None:
    with pytest.raises(ValidationError) as caught:
        shared("production", ALLOW_INSECURE_WEBHOOK_URLS=True)
    text = str(caught.value)
    assert "ALLOW_INSECURE_WEBHOOK_URLS" in text and ISSUER not in text.replace("input_value", "")
