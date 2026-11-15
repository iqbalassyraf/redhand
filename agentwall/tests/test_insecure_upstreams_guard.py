"""
ALLOW_INSECURE_UPSTREAMS switches off the destination check (http, private addresses). Outside development the gateway refuses to start with it
on (H2.5). The environment name is a free string here, so only a name known to be local is trusted: a typo such as "prod" fails closed.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentwall.config.settings import Settings


@pytest.mark.parametrize("environment", ["staging", "production", "prod", "Production", "live", ""])
def test_a_shared_or_unknown_environment_refuses_the_flag(environment: str) -> None:
    with pytest.raises(ValidationError) as caught:
        Settings(ENVIRONMENT=environment, ALLOW_INSECURE_UPSTREAMS=True)  # type: ignore[call-arg]
    assert "ALLOW_INSECURE_UPSTREAMS" in str(caught.value)


@pytest.mark.parametrize("environment", ["development", "test", "dev", "local", "Development"])
def test_a_local_environment_may_use_the_flag(environment: str) -> None:
    assert Settings(ENVIRONMENT=environment, ALLOW_INSECURE_UPSTREAMS=True).ALLOW_INSECURE_UPSTREAMS  # type: ignore[call-arg]


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_a_shared_environment_without_the_flag_starts(environment: str) -> None:
    assert Settings(ENVIRONMENT=environment).ALLOW_INSECURE_UPSTREAMS is False  # type: ignore[call-arg]
