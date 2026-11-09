"""
Radar evidence from real traffic (Phase 4 M4.6b): the gateway reports how many results it scanned and flagged (numbers only), core judges
whether an organization's own traffic is clean evidence for even CONSIDERING block mode, and none of it grants anything. Every condition is
tested on both sides of its limit and alone, so one weak spot cannot hide behind six strong ones.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest

from redhand_core.radar import readiness
from redhand_core.radar.models import KindInputs, ReadinessInputs, RuleCounts
from redhand_core.services import local_rpc
from redhand_core.services.local_store import DEFAULT_ORG_ID

from test_radar_findings import GATEWAY_HEADERS, Env, item
from test_telegram import OTHER_ORG

FP = "0123456789abcdef"
NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
WINDOW_START = datetime(2026, 11, 3, tzinfo=timezone.utc)


def kind_inputs(**over: Any) -> KindInputs:
    base: dict[str, Any] = dict(
        mode="observe", mode_changed_at=WINDOW_START - timedelta(days=1), scanned=250, dropped=0, errors=0, flagged=0, strong=0,
        fingerprints=[FP], rules={}, stored_occurrences={}, strong_open=0, false_alarm_rules=[], silences_in_window=0,
        max_findings_per_agent_day=0,
    )
    return KindInputs(**{**base, **over})


def judged(**over: Any):
    return readiness.judge_kind("injection", kind_inputs(**over), over.get("mode_changed_at", WINDOW_START - timedelta(days=1)) <= WINDOW_START)


def failed(check) -> set[str]:
    return {c.id for c in check.conditions if not c.passed}


# --- the judge: clean traffic is ready, and each condition fails on its own ----------------------------------------------

def test_clean_traffic_over_a_full_window_is_ready() -> None:
    check = judged()
    assert check.ready and failed(check) == set() and check.scanned == 250 and check.strong_rate == 0.0


@pytest.mark.parametrize(
    ("condition", "over"),
    [
        ("R1", {"mode": "off"}),
        ("R1", {"mode_changed_at": WINDOW_START + timedelta(hours=1)}),
        ("R2", {"scanned": 199}),
        ("R3", {"strong_open": 1}),
        ("R4", {"silences_in_window": 1}),
        ("R5", {"dropped": 3}),
        ("R5", {"errors": 3}),
        ("R5", {"max_findings_per_agent_day": 1000}),
        ("R5", {"stored_occurrences": {"RAD-INJ-001": 4}, "rules": {"RAD-INJ-001": RuleCounts(flagged=3, strong=1)}}),
        ("R5", {"stored_occurrences": {"RAD-INJ-001": 1}}),  # findings stored for a rule the gateway never counted
        ("R6", {"fingerprints": []}),
        ("R6", {"fingerprints": [FP, "ffffffffffffffff"]}),
        ("R6", {"fingerprints": ["unknown"]}),
        ("R6", {"fingerprints": [FP + "+model"]}),
        ("R7", {"strong": 9, "false_alarm_rules": ["RAD-INJ-008"], "rules": {"RAD-INJ-008": RuleCounts(flagged=9, strong=9)}}),
    ],
)
def test_each_condition_fails_on_its_own_and_blocks_readiness(condition: str, over: dict[str, Any]) -> None:
    check = judged(**over)
    assert failed(check) == {condition} and not check.ready


def test_several_weaknesses_are_all_reported_and_too_little_traffic_also_widens_the_false_alarm_range() -> None:
    assert failed(judged(scanned=10, strong_open=2, silences_in_window=1)) == {"R2", "R3", "R4", "R7"}  # 0 of 10 could still be a 28% false alarm rate


# --- limits, on both sides -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("scanned", "passes"), [(199, False), (200, True), (201, True)])
def test_traffic_limit_boundaries(scanned: int, passes: bool) -> None:
    assert ("R2" not in failed(judged(scanned=scanned))) is passes


@pytest.mark.parametrize(("scanned", "dropped", "passes"), [(298, 2, True), (297, 3, False), (990, 9, True), (989, 10, False)])
def test_loss_limit_is_below_one_percent_of_attempts(scanned: int, dropped: int, passes: bool) -> None:
    assert ("R5" not in failed(judged(scanned=scanned, dropped=dropped))) is passes


@pytest.mark.parametrize(("per_day", "passes"), [(999, True), (1000, False)])
def test_daily_cap_pressure_boundary(per_day: int, passes: bool) -> None:
    assert ("R5" not in failed(judged(max_findings_per_agent_day=per_day))) is passes


def test_stored_findings_may_equal_but_never_exceed_what_was_counted() -> None:
    rules = {"RAD-INJ-001": RuleCounts(flagged=3, strong=1)}
    assert "R5" not in failed(judged(stored_occurrences={"RAD-INJ-001": 3}, rules=rules))
    assert "R5" in failed(judged(stored_occurrences={"RAD-INJ-001": 4}, rules=rules))


@pytest.mark.parametrize(("false_alarms", "passes"), [(0, True), (1, True), (2, False)])
def test_false_alarm_limit_at_200_results_allows_at_most_one(false_alarms: int, passes: bool) -> None:
    check = judged(scanned=200, strong=false_alarms, false_alarm_rules=["RAD-INJ-008"] if false_alarms else [], rules={"RAD-INJ-008": RuleCounts(flagged=false_alarms, strong=false_alarms)})
    assert check.false_alarms_worst_case == false_alarms and ("R7" not in failed(check)) is passes


def test_a_false_alarm_counts_every_strong_flag_of_that_rule_not_just_the_reviewed_one() -> None:
    check = judged(scanned=1000, strong=40, false_alarm_rules=["RAD-INJ-008"], rules={"RAD-INJ-008": RuleCounts(flagged=40, strong=35), "RAD-INJ-001": RuleCounts(flagged=5, strong=5)})
    assert check.false_alarms_worst_case == 35 and "R7" in failed(check)  # 35 of 1000, though only one finding was marked


def test_a_rule_with_no_count_is_assumed_to_be_the_worst_case() -> None:
    check = judged(scanned=1000, strong=30, false_alarm_rules=["RAD-INJ-008"], rules={})
    assert check.false_alarms_worst_case == 30 and "R7" in failed(check)


def test_the_worst_case_is_capped_at_the_results_scanned_and_each_rule_counts_once() -> None:
    assert judged(scanned=250, strong=999, false_alarm_rules=["RAD-INJ-008"], rules={}).false_alarms_worst_case == 250
    two = judged(scanned=1000, strong=9, false_alarm_rules=["RAD-INJ-008", "RAD-INJ-008"], rules={"RAD-INJ-008": RuleCounts(flagged=9, strong=9)})
    assert two.false_alarms_worst_case == 9


def test_nothing_scanned_is_never_ready_and_has_no_rates() -> None:
    check = judged(scanned=0, fingerprints=[])
    assert not check.ready and check.strong_rate is None and check.false_alarm_upper is None and {"R2", "R6", "R7"} <= failed(check)


def test_the_response_says_blocking_is_not_available_and_judges_both_checks() -> None:
    response = readiness.judge(ReadinessInputs(now=NOW, window_start=WINDOW_START, kinds={"injection": kind_inputs(), "output": kind_inputs(mode="off")}))
    assert response.block_available is False and response.window_days == 7
    assert [(c.kind, c.ready) for c in response.checks] == [("injection", True), ("output", False)]
    assert "not available" in response.note


def test_a_missing_check_in_the_inputs_is_an_error_not_a_verdict() -> None:
    with pytest.raises(KeyError):
        readiness.judge(ReadinessInputs(now=NOW, window_start=WINDOW_START, kinds={"injection": kind_inputs()}))


def test_wilson_upper_is_the_formula_the_benchmark_uses() -> None:
    assert readiness.wilson_upper(0, 125) == pytest.approx(0.0298, abs=5e-5) and readiness.wilson_upper(0, 124) > 0.03
    assert readiness.wilson_upper(0, 0) == 1.0 and readiness.wilson_upper(5, 5) == 1.0


# --- the gateway's report: strict, numbers only, tenant-checked ----------------------------------------------------------------

def counts_item(org: str = DEFAULT_ORG_ID, kind: str = "injection", **over: Any) -> dict[str, Any]:
    return {"organization_id": org, "kind": kind, "scanned": 250, "dropped": 0, "errors": 0, "flagged": 0, "strong": 0, "rules": [], **over}


def post_counts(env: Env, items: list[dict[str, Any]], fingerprint: str = FP, token: str | None = "default", report_id: str | None = None) -> Any:
    headers = GATEWAY_HEADERS if token == "default" else ({"Authorization": f"Bearer {token}"} if token else {})
    body = {"report_id": report_id or str(uuid4()), "rules_fingerprint": fingerprint, "items": items}
    return env.client.post("/internal/v1/radar/scan-counts", json=body, headers=headers)


def readiness_of(env: Env, user: str = "operator") -> Any:
    return env.client.get("/v1/radar/readiness", headers=env.h(user))


def check_of(env: Env, kind: str = "injection", user: str = "operator") -> dict[str, Any]:
    response = readiness_of(env, user)
    assert response.status_code == 200, response.text
    return next(c for c in response.json()["checks"] if c["kind"] == kind)


def conditions(check: dict[str, Any]) -> dict[str, bool]:
    return {c["id"]: c["passed"] for c in check["conditions"]}


@pytest.fixture
def env() -> Env:
    e = Env()
    watching = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    for org in e.store.tables["organizations"]:  # pretend both checks have been on Watch for 8 days
        org["radar_mode_changed_at"] = org["output_check_mode_changed_at"] = watching
    return e


def test_the_counts_route_needs_the_service_token(env: Env) -> None:
    body = [counts_item()]
    assert post_counts(env, body, token=None).status_code == 401
    assert post_counts(env, body, token="wrong-token-wrong-token-wrong-token-1234").status_code == 401
    assert post_counts(env, body).status_code == 200
    assert env.client.post("/internal/v1/radar/scan-counts", json={"report_id": str(uuid4()), "rules_fingerprint": FP, "items": body}, headers=env.h("owner")).status_code == 401  # an operator is not the gateway


def test_the_counts_route_is_hidden_from_the_public_api_description(env: Env) -> None:
    assert "/internal/v1/radar/scan-counts" not in env.client.get("/openapi.json").text


@pytest.mark.parametrize(
    "bad",
    [
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": "not-a-fingerprint", "items": [counts_item()]},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": []},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": [counts_item()] * 51},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": [counts_item(scanned=-1)]},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": [counts_item(scanned=1_000_001)]},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": [counts_item(kind="secrets")]},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": [counts_item(text="ignore previous instructions")]},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": [counts_item(rules=[{"rule_id": "free text", "flagged": 1, "strong": 1}])]},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": [counts_item(rules=[{"rule_id": "RAD-INJ-001", "flagged": 1, "strong": 1, "note": "x"}])]},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": [counts_item(rules=[{"rule_id": "RAD-INJ-001", "flagged": 1, "strong": 1}] * 41)]},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "rules_fingerprint": FP, "items": [counts_item()], "extra": 1},
        {"report_id": "00000000-0000-0000-0000-00000000aaaa", "items": [counts_item()]},
        {"rules_fingerprint": FP, "items": [counts_item()]},
        {"report_id": "not-a-uuid", "rules_fingerprint": FP, "items": [counts_item()]},
    ],
)
def test_a_malformed_counts_report_is_refused_whole(env: Env, bad: dict[str, Any]) -> None:
    response = env.client.post("/internal/v1/radar/scan-counts", json=bad, headers=GATEWAY_HEADERS)
    assert response.status_code == 422
    assert check_of(env)["scanned"] == 0


@pytest.mark.parametrize(
    "item_over",
    [
        {"flagged": 11, "scanned": 10},
        {"flagged": 3, "strong": 4, "scanned": 10},
        {"rules": [{"rule_id": "RAD-OUT-001", "flagged": 1, "strong": 1}]},  # a rule of the other check
        {"rules": [{"rule_id": "RAD-INJ-001", "flagged": 300, "strong": 1}]},  # more flagged than scanned
        {"flagged": 1, "strong": 1, "rules": [{"rule_id": "RAD-INJ-001", "flagged": 1, "strong": 2}]},
    ],
)
def test_an_inconsistent_item_is_skipped_whole_and_counted_not_stored(env: Env, item_over: dict[str, Any]) -> None:
    response = post_counts(env, [counts_item(**item_over)])
    assert response.status_code == 200 and response.json() == {"recorded": 0, "skipped": 1, "duplicate": False}
    assert check_of(env)["scanned"] == 0
    assert env.store.tables.get("radar_rule_counts", []) == []


def test_the_same_report_sent_twice_is_counted_once(env: Env) -> None:
    same = str(uuid4())
    first = post_counts(env, [counts_item(scanned=100, flagged=2, strong=1)], report_id=same)
    again = post_counts(env, [counts_item(scanned=100, flagged=2, strong=1)], report_id=same)  # a retry after a timeout, or a double delivery
    assert first.json() == {"recorded": 1, "skipped": 0, "duplicate": False} and again.json() == {"recorded": 0, "skipped": 0, "duplicate": True}
    assert check_of(env)["scanned"] == 100
    post_counts(env, [counts_item(scanned=100, flagged=2, strong=1)])  # a new report id is a new report
    assert check_of(env)["scanned"] == 200


def test_an_unknown_organization_is_skipped_and_a_good_item_in_the_same_report_still_counts(env: Env) -> None:
    response = post_counts(env, [counts_item(org="00000000-0000-0000-0000-00000000dead"), counts_item()])
    assert (response.json()["recorded"], response.json()["skipped"]) == (1, 1)
    assert check_of(env)["scanned"] == 250


def test_counts_are_kept_per_organization_and_one_cannot_see_the_others(env: Env) -> None:
    assert post_counts(env, [counts_item(org=OTHER_ORG, scanned=900, flagged=40, strong=30)]).json()["recorded"] == 1
    mine = check_of(env)
    assert mine["scanned"] == 0 and mine["strong"] == 0 and mine["strong_rate"] is None
    post_counts(env, [counts_item()])
    assert check_of(env)["scanned"] == 250


def test_counts_add_up_across_reports_and_the_two_checks_stay_apart(env: Env) -> None:
    post_counts(env, [counts_item(scanned=100, flagged=4, strong=2), counts_item(kind="output", scanned=70)])
    post_counts(env, [counts_item(scanned=160, flagged=1, strong=1)])
    injection, output = check_of(env), check_of(env, "output")
    assert (injection["scanned"], injection["strong"]) == (260, 3) and output["scanned"] == 70
    assert injection["strong_rate"] == pytest.approx(3 / 260)


# --- the readiness route --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 200), ("admin", 200), ("owner", 200)])
def test_only_a_security_operator_or_above_may_read_readiness(env: Env, user: str, expected: int) -> None:
    assert readiness_of(env, user).status_code == expected
    assert env.client.get("/v1/radar/readiness").status_code == 401


def test_a_fresh_organization_is_not_ready_and_blocking_is_not_available(env: Env) -> None:
    body = readiness_of(env).json()
    assert body["block_available"] is False and body["window_days"] == 7 and [c["ready"] for c in body["checks"]] == [False, False]
    assert env.settings_get().json()["block_available"] is False


def test_real_looking_clean_traffic_becomes_ready_and_ready_changes_nothing(env: Env) -> None:
    post_counts(env, [counts_item(), counts_item(kind="output")])
    assert check_of(env)["ready"] and check_of(env, "output")["ready"]
    assert env.settings_get().json()["radar_mode"] == "observe"
    for body in ({"radar_mode": "block", "output_check_mode": "observe"}, {"radar_mode": "observe", "output_check_mode": "block"}):
        assert env.client.put("/v1/radar/settings", json=body, headers=env.h("admin")).status_code == 422  # ready is not permission
    assert env.settings_get().json()["radar_mode"] == "observe" and env.settings_get().json()["block_available"] is False


def test_the_whole_story_a_finding_a_review_a_silence_and_a_mode_change(env: Env) -> None:
    flagged_rule = [{"rule_id": "RAD-INJ-001", "flagged": 1, "strong": 1}]
    post_counts(env, [counts_item(flagged=1, strong=1, rules=flagged_rule)])
    assert conditions(check_of(env)) == dict.fromkeys(["R1", "R2", "R3", "R4", "R5", "R6", "R7"], True)

    assert env.report([item("RAD-INJ-001", would_block=True)]).status_code == 200  # a strong finding arrives, still open
    check = check_of(env)
    assert conditions(check)["R3"] is False and not check["ready"]
    finding = env.first_finding()
    assert env.review(finding, "confirmed").status_code == 200  # a real attack, reviewed
    assert check_of(env)["ready"]

    assert env.review(finding, "false_alarm").status_code == 200  # changed to a false alarm: 1 of 250 counted
    check = check_of(env)
    assert check["false_alarms_worst_case"] == 1 and conditions(check)["R7"] is True and check["ready"]

    assert env.suppress("RAD-INJ-001").status_code == 200  # a silence hides findings, so the evidence stops counting
    assert conditions(check_of(env))["R4"] is False and conditions(check_of(env, "output"))["R4"] is True
    suppression = env.suppressions().json()["suppressions"][0]["id"]
    assert env.client.delete(f"/v1/radar/suppressions/{suppression}", headers=env.h("admin")).status_code == 200
    assert conditions(check_of(env))["R4"] is False  # revoked, but it was live inside the window

    assert env.settings_put("off", "observe", confirm=True).status_code == 200
    assert conditions(check_of(env))["R1"] is False and conditions(check_of(env, "output"))["R1"] is True


def test_false_alarms_never_exceed_the_results_with_a_strong_finding_even_when_rules_overlap() -> None:
    """The M4.6 staging run: 36 results had a strong injection finding, yet five reviewed rules' own counts add up to 45 because one document is
    counted under every rule that flagged it. A result is one false alarm however many rules flagged it, so the figure is capped at the strong results."""
    rules = {"RAD-INJ-002": RuleCounts(flagged=2, strong=2), "RAD-INJ-003": RuleCounts(flagged=48, strong=30), "RAD-INJ-004": RuleCounts(flagged=1, strong=1),
             "RAD-INJ-005": RuleCounts(flagged=10, strong=10), "RAD-INJ-007": RuleCounts(flagged=2, strong=2)}
    check = judged(scanned=100, strong=36, false_alarm_rules=sorted(rules), rules=rules)
    assert check.false_alarms_worst_case == 36
    assert check.false_alarms_worst_case <= check.strong


def test_the_cap_does_not_hide_a_larger_figure_the_other_way_round() -> None:
    rules = {"RAD-INJ-003": RuleCounts(flagged=30, strong=30), "RAD-INJ-005": RuleCounts(flagged=10, strong=10)}
    assert judged(scanned=100, strong=60, false_alarm_rules=sorted(rules), rules=rules).false_alarms_worst_case == 40  # rules overlap less than the cap allows
    assert judged(scanned=100, strong=40, false_alarm_rules=sorted(rules), rules=rules).false_alarms_worst_case == 40  # exactly at the cap


def test_a_gap_between_what_was_stored_and_what_was_counted_is_noticed(env: Env) -> None:
    post_counts(env, [counts_item()])  # the gateway's count report arrived but said nothing was flagged
    assert env.report([item("RAD-INJ-001", would_block=True, occurrences=3)]).status_code == 200
    env.review(env.first_finding(), "confirmed")
    check = check_of(env)
    assert conditions(check)["R5"] is False and not check["ready"]  # 3 stored, 0 counted: counts were lost somewhere


def test_one_false_alarm_among_many_flags_counts_all_of_them(env: Env) -> None:
    rules = [{"rule_id": "RAD-INJ-008", "flagged": 12, "strong": 12}]
    post_counts(env, [counts_item(flagged=12, strong=12, rules=rules)])
    env.report([item("RAD-INJ-008", would_block=True, occurrences=1)])
    env.review(env.first_finding(), "false_alarm")
    check = check_of(env)
    assert check["false_alarms_worst_case"] == 12 and conditions(check)["R7"] is False and check["false_alarm_upper"] > 0.03


def test_a_mode_changed_inside_the_window_resets_the_evidence(env: Env) -> None:
    post_counts(env, [counts_item()])
    for org in env.store.tables["organizations"]:
        org["radar_mode_changed_at"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    check = check_of(env)
    assert conditions(check)["R1"] is False and not check["ready"] and conditions(check_of(env, "output"))["R1"] is True


def test_the_window_is_the_last_seven_utc_days(env: Env) -> None:
    post_counts(env, [counts_item(scanned=100)])
    for row in env.store.tables["radar_scan_counts"]:
        row["day"] = (datetime.now(timezone.utc).date() - timedelta(days=7)).isoformat()
    assert check_of(env)["scanned"] == 0  # seven days ago is outside
    for row in env.store.tables["radar_scan_counts"]:
        row["day"] = (datetime.now(timezone.utc).date() - timedelta(days=6)).isoformat()
    assert check_of(env)["scanned"] == 100


def test_unreadable_inputs_are_an_error_and_never_a_verdict(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(local_rpc.HANDLERS, "radar_readiness_inputs", lambda store, p: {"unexpected": True})
    response = readiness_of(env)
    assert response.status_code == 503 and "ready" not in response.text
    monkeypatch.setitem(local_rpc.HANDLERS, "radar_readiness_inputs", lambda store, p: {"now": "2026-11-09T00:00:00+00:00", "window_start": "2026-11-03T00:00:00+00:00", "kinds": {}})
    assert readiness_of(env).status_code == 503


def test_the_counts_hold_numbers_only(env: Env) -> None:
    post_counts(env, [counts_item(flagged=1, strong=1, rules=[{"rule_id": "RAD-INJ-001", "flagged": 1, "strong": 1}])])
    for table in ("radar_scan_counts", "radar_rule_counts"):
        for row in env.store.tables[table]:
            assert all(isinstance(v, (int, str)) for v in row.values()) and set(row) <= {
                "organization_id", "day", "kind", "rules_fingerprint", "rule_id", "scanned", "dropped", "errors", "flagged", "strong",
            }
