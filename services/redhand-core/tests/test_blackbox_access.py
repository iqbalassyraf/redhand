"""
Black Box access (Phase 3 M2c): reading one captured payload and exporting the timeline. Both are admin or
operator gated, audited, tenant scoped and never cached.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any

import pytest

from redhand_core.blackbox import service as blackbox_service
from redhand_core.routers import blackbox as blackbox_router
from redhand_core.services import local_rpc
from redhand_core.services.local_store import DEFAULT_ORG_ID

from test_blackbox import FINOPS_AGENT_ID, SECOPS_AGENT_ID, Env, _capture, _event, _excerpt

SECRET_TEXT = "{\"note\":\"payload-text-that-must-not-leak\"}"


@pytest.fixture(autouse=True)
def _fresh_limiters() -> None:
    blackbox_router._payload_limiter._events.clear()
    blackbox_router._export_limiter._events.clear()


def _audit(env: Env, action: str) -> list[dict[str, Any]]:
    return [r for r in env.store.tables.get("control_audit_log", []) if r["action"] == action]


def _env_with_payload() -> Env:
    env = Env()
    assert _capture(env, enabled=True, confirm=True).status_code == 200
    env.ingest([
        _event(FINOPS_AGENT_ID, arguments_redacted=_excerpt(SECRET_TEXT), result_excerpt=_excerpt("ok")),
        _event(SECOPS_AGENT_ID, decision="BLOCK"),
    ])
    return env


def _view(env: Env, seq: int, user: str = "admin") -> Any:
    return env.client.get(f"/v1/blackbox/events/{seq}/payload", headers=env.h(user))


def _export(env: Env, user: str = "operator", **params: Any) -> Any:
    return env.client.get("/v1/blackbox/export", params=params, headers=env.h(user))


def _jsonl(resp: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    lines = [json.loads(line) for line in resp.text.splitlines()]
    return lines[:-1], lines[-1]


# --- payload view ------------------------------------------------------------------------------------------

def test_an_admin_reads_a_payload_and_the_read_is_audited() -> None:
    env = _env_with_payload()
    resp = _view(env, 1)
    assert resp.status_code == 200
    body = resp.json()
    assert body["seq"] == 1 and body["arguments_redacted"]["text"] == SECRET_TEXT and body["result_excerpt"]["text"] == "ok"
    (audit,) = _audit(env, "organization.blackbox_payload_viewed")
    assert audit["actor_user_id"] == "00000000-0000-0000-0000-0000000000a2"
    assert audit["details"] == {"seq": 1, "had_arguments": True, "had_result": True}
    assert "payload-text-that-must-not-leak" not in json.dumps(audit)


def test_an_event_without_a_payload_returns_nulls_and_is_still_audited() -> None:
    env = _env_with_payload()
    body = _view(env, 2).json()
    assert body["arguments_redacted"] is None and body["result_excerpt"] is None
    assert _audit(env, "organization.blackbox_payload_viewed")[0]["details"]["had_arguments"] is False


@pytest.mark.parametrize(("user", "expected"), [("viewer", 403), ("operator", 403), ("admin", 200), ("owner", 200)])
def test_only_admins_and_owners_can_read_payloads(user: str, expected: int) -> None:
    env = _env_with_payload()
    assert _view(env, 1, user).status_code == expected
    assert len(_audit(env, "organization.blackbox_payload_viewed")) == (1 if expected == 200 else 0)


def test_a_missing_event_is_404_and_leaves_no_audit_row() -> None:
    env = _env_with_payload()
    assert _view(env, 999).status_code == 404
    assert _audit(env, "organization.blackbox_payload_viewed") == []
    assert env.client.get("/v1/blackbox/events/0/payload", headers=env.h("admin")).status_code == 422


def test_another_organizations_event_cannot_be_read() -> None:
    env = _env_with_payload()
    resp = env.client.get("/v1/blackbox/events/1/payload", headers=env.h_other_org())
    assert resp.status_code == 404 and "payload-text" not in resp.text
    assert _audit(env, "organization.blackbox_payload_viewed") == []


def test_no_payload_is_returned_when_the_audited_read_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    env = _env_with_payload()

    def broken(store: Any, p: dict[str, Any]) -> Any:
        raise local_rpc._error("XX000", "boom")

    monkeypatch.setitem(local_rpc.HANDLERS, "read_event_payload", broken)
    resp = _view(env, 1)
    assert resp.status_code == 503 and "payload-text" not in resp.text


def test_payload_responses_are_not_cacheable() -> None:
    env = _env_with_payload()
    assert _view(env, 1).headers["cache-control"] == "no-store"


def test_payload_views_are_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    env = _env_with_payload()
    monkeypatch.setattr(blackbox_router, "PAYLOAD_VIEWS_PER_MINUTE", 2)
    assert [_view(env, 1).status_code for _ in range(3)] == [200, 200, 429]


def test_payload_text_is_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    env = _env_with_payload()
    with caplog.at_level(logging.DEBUG):
        _view(env, 1)
        _export(env, "admin", include_payloads="true")
    assert "payload-text-that-must-not-leak" not in caplog.text


# --- capabilities ------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("user", "expected"),
    [
        ("viewer", (False, False, False, False, False)),
        ("operator", (False, True, False, True, False)),
        ("admin", (True, True, True, True, True)),
        ("owner", (True, True, True, True, True)),
    ],
)
def test_settings_tell_the_dashboard_what_the_role_may_do(user: str, expected: tuple[bool, ...]) -> None:
    caps = Env().client.get("/v1/blackbox/settings", headers=Env().h(user)).json()["capabilities"]
    assert (
        caps["can_manage"], caps["can_turn_capture_off"], caps["can_view_payloads"], caps["can_export"],
        caps["can_export_payloads"],
    ) == expected


def test_capabilities_are_not_added_to_write_responses() -> None:
    env = Env()
    resp = env.client.put("/v1/blackbox/payload-capture", json={"enabled": False}, headers=env.h("operator"))
    assert resp.status_code == 200 and resp.json()["capabilities"] is None


# --- export ------------------------------------------------------------------------------------------------

def test_a_security_operator_exports_metadata_as_json_lines_and_it_is_audited() -> None:
    env = _env_with_payload()
    resp = _export(env)
    assert resp.status_code == 200 and resp.headers["cache-control"] == "no-store"
    assert "attachment" in resp.headers["content-disposition"] and ".jsonl" in resp.headers["content-disposition"]
    rows, trailer = _jsonl(resp)
    assert [r["seq"] for r in rows] == [1, 2]  # oldest first
    assert trailer == {"export_complete": True, "rows": 2, "capped_at": None}
    assert all("arguments_redacted" not in r for r in rows) and "payload-text" not in resp.text
    (audit,) = _audit(env, "organization.blackbox_exported")
    assert audit["details"]["include_payloads"] is False and audit["details"]["format"] == "jsonl"
    assert audit["actor_user_id"] == "00000000-0000-0000-0000-0000000000a3"


def test_exporting_payloads_needs_admin_and_includes_the_excerpts() -> None:
    env = _env_with_payload()
    assert _export(env, "operator", include_payloads="true").status_code == 403
    assert _audit(env, "organization.blackbox_exported") == []
    rows, _ = _jsonl(_export(env, "admin", include_payloads="true"))
    assert rows[0]["arguments_redacted"]["text"] == SECRET_TEXT and rows[1]["arguments_redacted"] is None
    assert _audit(env, "organization.blackbox_exported")[0]["details"]["include_payloads"] is True


def test_viewers_cannot_export() -> None:
    env = _env_with_payload()
    assert _export(env, "viewer").status_code == 403
    assert _audit(env, "organization.blackbox_exported") == []


def test_an_export_contains_only_the_callers_organization() -> None:
    env = _env_with_payload()
    rows, trailer = _jsonl(env.client.get("/v1/blackbox/export", headers=env.h_other_org()))
    assert rows == [] and trailer["rows"] == 0


def test_export_filters() -> None:
    env = _env_with_payload()
    rows, _ = _jsonl(_export(env, decision="BLOCK"))
    assert [r["seq"] for r in rows] == [2]
    rows, _ = _jsonl(_export(env, agent_id=FINOPS_AGENT_ID))
    assert [r["seq"] for r in rows] == [1]
    rows, _ = _jsonl(_export(env, since="2999-01-01T00:00:00+00:00"))
    assert rows == []
    assert _export(env, since="2026-02-01T00:00:00+00:00", until="2026-01-01T00:00:00+00:00").status_code == 400
    assert _export(env, decision="MAYBE").status_code == 422
    assert _export(env, format="xml").status_code == 422


def test_the_export_audit_failure_stops_the_export(monkeypatch: pytest.MonkeyPatch) -> None:
    env = _env_with_payload()

    def broken(store: Any, p: dict[str, Any]) -> Any:
        raise local_rpc._error("XX000", "boom")

    monkeypatch.setitem(local_rpc.HANDLERS, "audit_blackbox_export", broken)
    resp = _export(env, "admin", include_payloads="true")
    assert resp.status_code == 503 and "payload-text" not in resp.text


def test_the_row_cap_is_reported_in_the_trailer(monkeypatch: pytest.MonkeyPatch) -> None:
    env = Env()
    env.ingest([_event(FINOPS_AGENT_ID) for _ in range(7)])
    monkeypatch.setattr(blackbox_service, "MAX_EXPORT_ROWS", 5)
    rows, trailer = _jsonl(_export(env))
    assert len(rows) == 5 and trailer == {"export_complete": False, "rows": 5, "capped_at": 5}
    monkeypatch.setattr(blackbox_service, "MAX_EXPORT_ROWS", 7)  # exactly the size: complete, not capped
    _, trailer = _jsonl(_export(env))
    assert trailer["export_complete"] is True and trailer["rows"] == 7


def test_rows_are_read_in_bounded_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    env = Env()
    env.ingest([_event(FINOPS_AGENT_ID) for _ in range(8)])
    sizes: list[int] = []
    original = blackbox_service._export_query

    async def spy(supabase: Any, org: Any, columns: str, after: int, size: int, *rest: Any) -> Any:
        sizes.append(size)
        return await original(supabase, org, columns, after, size, *rest)

    monkeypatch.setattr(blackbox_service, "_export_query", spy)
    monkeypatch.setattr(blackbox_service, "EXPORT_CHUNK", 3)
    rows, trailer = _jsonl(_export(env))
    assert [r["seq"] for r in rows] == list(range(1, 9)) and trailer["rows"] == 8
    assert max(sizes) <= 3 and len(sizes) == 3


def test_csv_export_escapes_formulas_and_parses() -> None:
    env = Env()
    env.ingest([_event(FINOPS_AGENT_ID, tool="=HYPERLINK(\"http://evil\")"), _event(FINOPS_AGENT_ID, tool="@SUM(1)"),
                _event(FINOPS_AGENT_ID, tool="-2+3"), _event(FINOPS_AGENT_ID, tool="+1"), _event(FINOPS_AGENT_ID, tool="plain, with comma")])
    resp = _export(env, format="csv")
    assert resp.headers["content-type"].startswith("text/csv") and ".csv" in resp.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0][:3] == ["seq", "occurred_at", "agent_id"]
    tools = [r[5] for r in rows[1:]]
    assert tools == ["'=HYPERLINK(\"http://evil\")", "'@SUM(1)", "'-2+3", "'+1", "plain, with comma"]
    assert all(not cell.startswith(("=", "+", "-", "@")) for r in rows[1:] for cell in r if cell and not cell[0].isdigit())


def test_csv_payload_columns_only_appear_when_payloads_are_included() -> None:
    env = _env_with_payload()
    plain = list(csv.reader(io.StringIO(_export(env, format="csv").text)))
    assert "arguments_redacted" not in plain[0]
    full = list(csv.reader(io.StringIO(_export(env, "admin", format="csv", include_payloads="true").text)))
    assert full[0][-2:] == ["arguments_redacted", "result_excerpt"] and full[1][-2] == SECRET_TEXT


def test_exports_are_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    env = _env_with_payload()
    monkeypatch.setattr(blackbox_router, "EXPORTS_PER_HOUR", 2)
    assert [_export(env).status_code for _ in range(3)] == [200, 200, 429]


def test_the_default_organization_id_is_the_one_used() -> None:
    assert DEFAULT_ORG_ID  # guards the fixtures above against an import that silently changes tenants


# --- delete captured payloads now --------------------------------------------------------------------------

def _clear(env: Env, user: str = "admin", **body: Any) -> Any:
    return env.client.post("/v1/blackbox/payloads/clear", json=body, headers=env.h(user))


def test_an_admin_clears_every_payload_and_the_chain_still_verifies() -> None:
    env = _env_with_payload()
    resp = _clear(env, confirm=True, reason="customer asked")
    assert resp.status_code == 200 and resp.json() == {"cleared": 1}
    assert _view(env, 1).json()["arguments_redacted"] is None
    assert env.verify(1, 2).json()["ok"] is True
    (audit,) = _audit(env, "organization.blackbox_payloads_cleared")
    assert audit["details"] == {"events_cleared": 1} and "payload-text" not in json.dumps(audit)
    assert _clear(env, confirm=True).json() == {"cleared": 0}  # repeating is harmless and not audited again
    assert len(_audit(env, "organization.blackbox_payloads_cleared")) == 1


def test_clearing_needs_confirmation_and_changes_nothing_without_it() -> None:
    env = _env_with_payload()
    assert _clear(env).status_code == 400
    assert _view(env, 1).json()["arguments_redacted"] is not None


@pytest.mark.parametrize("user", ["viewer", "operator"])
def test_only_admins_can_clear_payloads(user: str) -> None:
    env = _env_with_payload()
    assert _clear(env, user, confirm=True).status_code == 403
    assert _view(env, 1).json()["arguments_redacted"] is not None


def test_clearing_never_touches_another_organization() -> None:
    env = _env_with_payload()
    assert env.client.post(
        "/v1/blackbox/payloads/clear", json={"confirm": True}, headers=env.h_other_org()
    ).json() == {"cleared": 0}
    assert _view(env, 1).json()["arguments_redacted"] is not None
