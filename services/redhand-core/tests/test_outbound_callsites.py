"""
The webhook guard at each place core calls a customer-supplied URL (H2.1): Slack, the SIEM export, the resume webhook; and the ingest check
that refuses an unusable URL at submission. A refused URL is permanent (no retry), is counted, and is logged as its host only.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from redhand_core.config import get_settings
from redhand_core.net import outbound
from redhand_core.routers import telemetry
from redhand_core.routers.hitl import trigger_agent_resume_webhook
from redhand_core.services.metrics import get_metrics
from redhand_core.services.notifications import slack
from redhand_core.services.siem_exporter import SIEMExporter

SECRET = "TopSecretPathToken0123456789"
BLOCKED = f"https://169.254.169.254/latest/meta-data/{SECRET}"
INTERVENTION = {"id": "i-1", "agent_id": "a", "tool_name": "t", "tool_arguments": {}}


class _Supabase:
    """Just enough of the client for the resume path: records the status written."""

    def __init__(self) -> None:
        self.updates: list[dict[str, Any]] = []

    def table(self, name: str) -> _Supabase:
        return self

    def update(self, values: dict[str, Any]) -> _Supabase:
        self.updates.append(values)
        return self

    def eq(self, column: str, value: str) -> _Supabase:
        return self

    async def execute(self) -> None:
        return None


@pytest.fixture
def requests_made(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Any request that gets past the guard lands here instead of the network."""
    targets: list[str] = []

    async def send(http: object, target: str, *args: object, **kwargs: object) -> outbound.OutboundResponse:
        targets.append(target)
        return outbound.OutboundResponse(200, b"")

    monkeypatch.setattr(outbound, "send_post", send)
    return targets


def _blocked_count(purpose: str) -> float:
    series = get_metrics()._counters["redhand_outbound_blocked_total"]  # noqa: SLF001 - the registry has no public reader
    return series.get((("purpose", purpose),), 0.0)


@pytest.fixture(autouse=True)
def _default_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("ALLOW_INSECURE_WEBHOOK_URLS", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_slack_refuses_a_metadata_address_counts_it_and_logs_only_the_host(
    requests_made: list[str], caplog: pytest.LogCaptureFixture
) -> None:
    before = _blocked_count("slack")
    caplog.set_level(logging.DEBUG)
    assert await slack.dispatch_slack_hitl_notification(BLOCKED, INTERVENTION) is False
    assert requests_made == []
    assert _blocked_count("slack") == before + 1
    assert SECRET not in caplog.text and "169.254.169.254" in caplog.text


@pytest.mark.asyncio
async def test_siem_refuses_a_blocked_url_without_retrying(requests_made: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []

    async def no_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("redhand_core.services.siem_exporter.asyncio.sleep", no_sleep)
    before = _blocked_count("siem")
    exporter = SIEMExporter(max_retries=3)
    assert await exporter.export_events(siem_webhook_url=BLOCKED, security_event_rows=[{"id": "e1"}]) is False
    assert requests_made == [] and slept == [], "a refused URL must not be retried"
    assert _blocked_count("siem") == before + 1


@pytest.mark.asyncio
async def test_resume_webhook_refuses_a_blocked_url_and_marks_the_intervention_failed(
    requests_made: list[str], caplog: pytest.LogCaptureFixture
) -> None:
    supabase = _Supabase()
    before = _blocked_count("resume")
    caplog.set_level(logging.DEBUG)
    await trigger_agent_resume_webhook(
        intervention_id=uuid4(), resume_webhook_url=BLOCKED, wake_payload={"decision": "approved"}, supabase=supabase  # type: ignore[arg-type]
    )
    assert requests_made == []
    assert supabase.updates == [{"status": "failed"}]
    assert _blocked_count("resume") == before + 1
    assert SECRET not in caplog.text


@pytest.mark.asyncio
async def test_a_resume_webhook_that_passes_the_guard_is_called_and_resumes(
    requests_made: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def public(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr(outbound, "system_resolver", public)
    supabase = _Supabase()
    await trigger_agent_resume_webhook(
        intervention_id=uuid4(), resume_webhook_url="https://agents.example.com/resume", wake_payload={}, supabase=supabase  # type: ignore[arg-type]
    )
    assert len(requests_made) == 1 and "93.184.216.34" in requests_made[0]
    assert supabase.updates and supabase.updates[0]["status"] == "resumed"


@pytest.mark.asyncio
async def test_the_development_flag_allows_a_local_http_url(requests_made: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOW_INSECURE_WEBHOOK_URLS", "true")
    get_settings.cache_clear()
    supabase = _Supabase()
    await trigger_agent_resume_webhook(
        intervention_id=uuid4(), resume_webhook_url="http://localhost:9000/resume", wake_payload={}, supabase=supabase  # type: ignore[arg-type]
    )
    assert requests_made == ["http://localhost:9000/resume"]
    assert supabase.updates[0]["status"] == "resumed"


def _checkpoint(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "proposed_tool_name": "send_email",
        "serialized_agent_state": {"k": "v"},
        "state_checksum": "0" * 64,
        "resume_webhook_url": "https://agents.example.com/resume",
    }
    body.update(overrides)
    return body


def test_ingest_accepts_a_public_https_webhook() -> None:
    parsed = telemetry.HITLCheckpointPayload.model_validate(
        _checkpoint(notification_webhook_url="https://hooks.slack.com/services/T/B/X")
    )
    assert str(parsed.resume_webhook_url) == "https://agents.example.com/resume"


@pytest.mark.parametrize(
    "field", ["resume_webhook_url", "notification_webhook_url"],
)
@pytest.mark.parametrize(
    "url",
    [
        "http://agents.example.com/resume",
        "https://localhost/resume",
        "https://127.0.0.1/resume",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.5/resume",
        "https://user:pw@agents.example.com/resume",
        "https://service.internal/resume",
    ],
)
def test_ingest_refuses_an_unusable_webhook_url(field: str, url: str) -> None:
    with pytest.raises(ValidationError) as caught:
        telemetry.HITLCheckpointPayload.model_validate(_checkpoint(**{field: url}))
    assert field in str(caught.value)


def test_ingest_allows_a_local_url_only_with_the_development_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        telemetry.HITLCheckpointPayload.model_validate(_checkpoint(resume_webhook_url="http://localhost:9000/r"))
    monkeypatch.setenv("ALLOW_INSECURE_WEBHOOK_URLS", "true")
    get_settings.cache_clear()
    telemetry.HITLCheckpointPayload.model_validate(_checkpoint(resume_webhook_url="http://localhost:9000/r"))
