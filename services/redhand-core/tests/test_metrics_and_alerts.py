"""
RedHand Core - Prometheus Metrics & PagerDuty Alerts Verification Suite
File: services/redhand-core/tests/test_metrics_and_alerts.py
"""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest
from pydantic import SecretStr

from redhand_core.config import get_settings
from redhand_core.main import create_app
from redhand_core.services.metrics import MetricsCollector
from redhand_core.services.notifications.pagerduty import dispatch_pagerduty_alert


def test_metrics_collector_prometheus_output() -> None:
    collector = MetricsCollector()
    collector.increment_counter("redhand_firewall_evaluations_total", 3.0, {"verdict": "blocked"})
    collector.set_gauge("redhand_hitl_interventions_active", 2.0)
    collector.record_histogram("redhand_firewall_latency_seconds", 0.012)

    rendered = collector.render_prometheus()
    assert "# TYPE redhand_firewall_evaluations_total counter" in rendered
    assert 'redhand_firewall_evaluations_total{verdict="blocked"} 3.0' in rendered
    assert "# TYPE redhand_hitl_interventions_active gauge" in rendered
    assert "redhand_hitl_interventions_active 2.0" in rendered
    assert "redhand_firewall_latency_seconds_bucket" in rendered
    assert rendered.endswith("\n")


@pytest.mark.asyncio
async def test_pagerduty_dispatch_mock() -> None:
    dispatched = await dispatch_pagerduty_alert(
        routing_key="mock_routing_key_12345",
        summary="Critical prompt injection attack detected on agent finops-prod",
        severity="critical",
        agent_id="agent-001",
    )
    assert dispatched is True


METRICS_TOKEN = "test-service-token-for-metrics"


def _metrics_client(token: str | None) -> TestClient:
    app = create_app()
    settings = get_settings().model_copy(
        update={"INTERNAL_SERVICE_TOKEN": SecretStr(token) if token else None}
    )
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def test_metrics_http_endpoint_with_service_token() -> None:
    resp = _metrics_client(METRICS_TOKEN).get(
        "/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}"}
    )
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "redhand_firewall_evaluations_total" in resp.text


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong-token"}, {"Authorization": "Basic abc"}],
)
def test_metrics_refused_without_the_service_token(headers: dict[str, str]) -> None:
    resp = _metrics_client(METRICS_TOKEN).get("/metrics", headers=headers)
    assert resp.status_code == 401
    assert "redhand_" not in resp.text


def test_metrics_fail_closed_when_no_service_token_is_configured() -> None:
    resp = _metrics_client(None).get("/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}"})
    assert resp.status_code == 503
    assert "redhand_" not in resp.text

