"""Shared fixtures for AgentWall tests."""

from collections.abc import Iterator
from typing import Any

import pytest

from agentwall.src.main import dispatcher


@pytest.fixture(autouse=True)
def fake_upstream(request: pytest.FixtureRequest) -> Iterator[list[dict[str, Any]]]:
    """
    Replaces the outbound HTTP call with an in-process fake tool server that records
    what it received. Tests marked `real_upstream` keep the real forwarder so they can
    exercise transport failures.
    """
    if request.node.get_closest_marker("real_upstream"):
        yield []
        return

    received: list[dict[str, Any]] = []

    async def _fake_forward(
        upstream_url: str, payload: dict[str, Any], ephemeral_token: str
    ) -> tuple[Any, int]:
        received.append({"url": upstream_url, "payload": payload})
        return {"content": [{"type": "text", "text": "fake upstream executed"}]}, 200

    original = dispatcher._forward_upstream
    dispatcher._forward_upstream = _fake_forward  # type: ignore[method-assign]  # test double
    try:
        yield received
    finally:
        dispatcher._forward_upstream = original  # type: ignore[method-assign]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "real_upstream: use the real upstream forwarder")
