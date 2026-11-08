"""
Radar self-test, core side (Phase 4 M4.5b): security operators and above, once a minute per organization, the gateway is called with the
service token and no input, the answer is validated, and a gateway that fails is an error: no result is ever invented.
"""

from __future__ import annotations

from typing import Any

import pytest

from redhand_core.routers import radar as radar_router

from test_mcp_scan import SERVICE_TOKEN, Env as ScanEnv, FakeGateway

OTHER_OWNER = "00000000-0000-0000-0000-0000000000f3"
URL = "/v1/radar/self-test"


def category(name: str, **over: Any) -> dict[str, Any]:
    base = {"category": name, "malicious": 20, "benign": 20, "detected": 19, "false_alarms": 0, "detection_low": 0.76, "detection_high": 0.99,
            "false_alarm_low": 0.0, "false_alarm_high": 0.16, "hard_benign": 10, "hard_false_alarms": 0}
    base.update(over)
    return base


def gateway_answer(**over: Any) -> dict[str, Any]:
    body = {"corpus": "1eef50813cce3eaa", "model_enabled": False, "samples": 160, "duration_ms": 57.0,
            "categories": [category("injection_indirect", malicious=28, benign=32, detected=23), category("output_path"), category("output_ssrf"), category("output_xss")],
            "limits": "This runs the Radar code in the gateway over our own held-out samples."}
    body.update(over)
    return body


@pytest.fixture(autouse=True)
def fresh_limiter() -> None:
    radar_router._self_test_last_run.clear()


def env(status: int = 200, body: Any = None, error: Exception | None = None, configured: bool = True) -> ScanEnv:
    return ScanEnv(FakeGateway(status, gateway_answer() if body is None else body, error), configured=configured)


def run(e: ScanEnv, user: str = "operator") -> Any:
    return e.client.post(URL, headers=e.h(user))


def test_a_security_operator_gets_the_counts_next_to_the_organizations_switches() -> None:
    e = env()
    response = run(e)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["samples"] == 160 and body["categories"][0]["category"] == "injection_indirect" and body["model_enabled"] is False
    assert body["radar_mode"] == "observe" and body["output_check_mode"] == "observe" and body["ran_at"]


def test_the_gateway_is_called_once_with_the_service_token_and_no_input() -> None:
    e = env()
    run(e)
    (call,) = e.gateway.calls
    assert call.url.path == "/internal/v1/radar/self-test" and call.headers["authorization"] == f"Bearer {SERVICE_TOKEN}" and call.content == b""


@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 200), ("admin", 200), ("owner", 200)])
def test_viewers_are_refused_and_everyone_above_may_run_it(user: str, expected: int) -> None:
    e = env()
    assert run(e, user).status_code == expected
    if expected == 403:
        assert e.gateway.calls == []


def test_no_login_is_refused_and_the_gateway_is_not_called() -> None:
    e = env()
    assert e.client.post(URL).status_code in (401, 403) and e.gateway.calls == []


def test_a_second_run_within_a_minute_is_refused_and_does_not_reach_the_gateway() -> None:
    e = env()
    assert run(e).status_code == 200
    again = run(e, "admin")
    assert again.status_code == 429 and int(again.headers["retry-after"]) >= 1 and len(e.gateway.calls) == 1


def test_a_run_is_allowed_again_after_a_minute(monkeypatch: pytest.MonkeyPatch) -> None:
    e = env()
    clock = {"now": 5000.0}
    monkeypatch.setattr(radar_router.time, "monotonic", lambda: clock["now"])
    assert run(e).status_code == 200
    clock["now"] += radar_router.SELF_TEST_INTERVAL_SECONDS - 1
    assert run(e).status_code == 429
    clock["now"] += 2
    assert run(e).status_code == 200


def test_a_failed_attempt_also_counts_so_a_down_gateway_is_not_hammered() -> None:
    e = env(error=__import__("httpx").ConnectError("refused"))
    assert run(e).status_code == 502
    assert run(e).status_code == 429


def test_organizations_have_separate_limits() -> None:
    from uuid import uuid4

    first, second = uuid4(), uuid4()
    assert radar_router._self_test_wait(first, 100.0) == 0.0
    assert radar_router._self_test_wait(second, 100.5) == 0.0  # the other organization is not held back by the first one's run
    assert radar_router._self_test_wait(first, 101.0) > 0.0 and radar_router._self_test_wait(second, 101.0) > 0.0


@pytest.mark.parametrize(("status", "expected"), [(429, 429), (401, 503), (500, 502), (503, 502), (404, 502)])
def test_gateway_failures_are_errors_with_plain_messages_and_no_result(status: int, expected: int) -> None:
    e = env(status=status, body={"detail": "internal stack trace /app/secret.py"})
    response = run(e)
    assert response.status_code == expected
    assert "categories" not in response.text and "secret.py" not in response.text and "trace" not in response.text


def test_an_unreachable_gateway_is_a_502_not_a_result() -> None:
    e = env(error=__import__("httpx").ConnectError("refused"))
    response = run(e)
    assert response.status_code == 502 and "categories" not in response.text


@pytest.mark.parametrize("bad", [
    b"not json", {"corpus": "x"}, gateway_answer(categories=[]), gateway_answer(samples=0), gateway_answer(extra="surprise"),
    gateway_answer(corpus="NOT HEX!"), gateway_answer(categories=[category("made_up_category")]),
    gateway_answer(categories=[category("output_xss", detection_high=1.5)]), gateway_answer(limits="x" * 600),
])
def test_a_malformed_or_surprising_gateway_answer_is_an_error_never_a_result(bad: Any) -> None:
    e = env(body=bad)
    response = run(e)
    assert response.status_code == 502 and "categories" not in response.text


def test_an_unconfigured_gateway_is_a_503_and_does_not_use_up_the_minute() -> None:
    e = env(configured=False)
    assert run(e).status_code == 503
    assert radar_router._self_test_last_run == {}


def test_the_settings_shown_are_the_organizations_current_ones() -> None:
    e = env()
    put = e.client.put("/v1/radar/settings", json={"radar_mode": "off", "output_check_mode": "observe", "confirm": True}, headers=e.h("admin"))
    assert put.status_code == 200, put.text
    body = run(e).json()
    assert body["radar_mode"] == "off" and body["output_check_mode"] == "observe"


def test_the_memory_of_runs_is_bounded() -> None:
    from uuid import uuid4

    for _ in range(radar_router.MAX_TRACKED_ORGANIZATIONS + 5):
        radar_router._self_test_wait(uuid4(), 1.0)
    assert len(radar_router._self_test_last_run) <= radar_router.MAX_TRACKED_ORGANIZATIONS
