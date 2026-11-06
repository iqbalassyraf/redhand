"""
Black Box Recorder (Phase 3, M1): the gateway's internal ingest endpoint, the operator-facing
timeline and verify endpoints, tenant isolation, and the hash chain's tamper detection.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr

from redhand_core.services.local_store import DEFAULT_ORG_ID, LocalSupabaseAdapter

from core_helpers import make_client, operator_headers

SERVICE_TOKEN = "blackbox-test-internal-service-token-0123456789"
INSTANCE = "gateway-instance-cccc"
OTHER_ORG = "00000000-0000-0000-0000-0000000000f0"
OTHER_OWNER = "00000000-0000-0000-0000-0000000000f3"
FINOPS_AGENT_ID = "f91d4fae-7dec-11d0-a765-00a0c91e6bf6"
SECOPS_AGENT_ID = "a82c11bb-44c0-4a91-9b1c-82910fa3b201"


def _event(agent_id: str, decision: str = "ALLOW", tool: str = "read_file", **overrides: Any) -> dict[str, Any]:
    base = {
        "agent_id": agent_id,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "gateway_instance": INSTANCE,
        "server": "fs",
        "method": "tools/call",
        "tool_name": tool,
        "decision": decision,
        "reasons": [],
        "upstream_status": 200,
        "latency_ms": 1.5,
        "argument_keys": ["path"],
        "arguments_sha256": "a" * 64,
        "result_size_bytes": 100,
        "redaction_count": 0,
        "credential_jti": "jti-1",
    }
    base.update(overrides)
    return base


class Env:
    def __init__(self, **settings: Any) -> None:
        self.store = LocalSupabaseAdapter()
        self.store.tables["organizations"].append({
            "id": OTHER_ORG, "name": "Other", "slug": "other", "safe_mode": False,
            "blackbox_retention_days": 30, "payload_capture_enabled": False, "payload_retention_days": 7,
        })
        self.store.tables["organization_members"].append(
            {"id": str(uuid4()), "organization_id": OTHER_ORG, "user_id": OTHER_OWNER, "role": "owner"}
        )
        settings.setdefault("INTERNAL_SERVICE_TOKEN", SecretStr(SERVICE_TOKEN))
        self.client, self.settings = make_client(self.store, **settings)

    def h(self, user: str = "owner") -> dict[str, str]:
        return operator_headers(user, self.settings)

    def h_other_org(self) -> dict[str, str]:
        return operator_headers(settings=self.settings, user_id=UUID(OTHER_OWNER))

    def ingest(
        self, items: list[dict[str, Any]], org: str = DEFAULT_ORG_ID, batch_id: str | None = None,
        instance: str = INSTANCE, token: str | None = SERVICE_TOKEN,
    ) -> Any:
        body = {"instance_id": instance, "batch_id": batch_id or str(uuid4()), "organization_id": org, "items": items}
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.post("/internal/v1/events", json=body, headers=headers)

    def timeline(self, user: str = "owner", **params: Any) -> Any:
        return self.client.get("/v1/blackbox/events", params=params, headers=self.h(user))

    def verify(self, from_seq: int, to_seq: int, user: str = "owner") -> Any:
        return self.client.get("/v1/blackbox/verify", params={"from_seq": from_seq, "to_seq": to_seq}, headers=self.h(user))


def test_ingest_accepted_and_visible_in_timeline() -> None:
    env = Env()
    resp = env.ingest([_event(FINOPS_AGENT_ID), _event(FINOPS_AGENT_ID, decision="BLOCK", tool="delete_file")])
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"accepted": 2, "rejected": 0}

    page = env.timeline().json()
    assert len(page["events"]) == 2
    assert page["events"][0]["decision"] == "BLOCK"  # newest first
    assert page["events"][1]["decision"] == "ALLOW"
    assert page["next_before_seq"] is None


def test_refused_calls_are_recorded_too() -> None:
    env = Env()
    resp = env.ingest([_event(FINOPS_AGENT_ID, decision="BLOCK", tool="rm", reasons=["out_of_scope"])])
    assert resp.status_code == 200
    events = env.timeline().json()["events"]
    assert events[0]["decision"] == "BLOCK"
    assert events[0]["reasons"] == ["out_of_scope"]


def test_ingest_requires_the_internal_service_token() -> None:
    env = Env()
    assert env.ingest([_event(FINOPS_AGENT_ID)], token=None).status_code in (401, 403)
    assert env.ingest([_event(FINOPS_AGENT_ID)], token="wrong-token-0123456789012345").status_code in (401, 403)
    assert env.timeline().json()["events"] == []


def test_unknown_or_cross_tenant_agent_is_rejected_not_the_whole_batch() -> None:
    env = Env()
    unknown = str(uuid4())
    resp = env.ingest([_event(unknown), _event(FINOPS_AGENT_ID)], org=DEFAULT_ORG_ID)
    assert resp.status_code == 200
    assert resp.json() == {"accepted": 1, "rejected": 1}


def test_rejected_items_are_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Regression: record_events() once rejected every item (a database fault) while ingest still
    answered 200, and core logged nothing."""
    env = Env()
    with caplog.at_level(logging.WARNING, logger="redhand.core.blackbox"):
        resp = env.ingest([_event(str(uuid4())), _event(FINOPS_AGENT_ID)], org=DEFAULT_ORG_ID)
    assert resp.json() == {"accepted": 1, "rejected": 1}
    assert any("partly rejected" in r.getMessage() and "rejected=1" in r.getMessage() for r in caplog.records)


def test_a_fully_accepted_batch_logs_no_rejection(caplog: pytest.LogCaptureFixture) -> None:
    env = Env()
    with caplog.at_level(logging.WARNING, logger="redhand.core.blackbox"):
        env.ingest([_event(FINOPS_AGENT_ID)], org=DEFAULT_ORG_ID)
    assert not any("partly rejected" in r.getMessage() for r in caplog.records)


def test_duplicate_batch_id_is_a_noop() -> None:
    env = Env()
    batch = str(uuid4())
    first = env.ingest([_event(FINOPS_AGENT_ID), _event(FINOPS_AGENT_ID)], batch_id=batch)
    assert first.json() == {"accepted": 2, "rejected": 0}
    second = env.ingest([_event(FINOPS_AGENT_ID), _event(FINOPS_AGENT_ID)], batch_id=batch)
    assert second.json() == {"accepted": 2, "rejected": 0}
    assert len(env.timeline().json()["events"]) == 2  # not recorded twice


def test_timeline_pagination_and_filters() -> None:
    env = Env()
    env.ingest([_event(FINOPS_AGENT_ID) for _ in range(3)] + [_event(SECOPS_AGENT_ID, decision="BLOCK")])

    first_page = env.timeline(limit=2).json()
    assert len(first_page["events"]) == 2
    assert first_page["next_before_seq"] is not None

    second_page = env.timeline(limit=2, before_seq=first_page["next_before_seq"]).json()
    assert len(second_page["events"]) == 2
    assert second_page["next_before_seq"] is None

    only_blocks = env.timeline(decision="BLOCK").json()["events"]
    assert len(only_blocks) == 1 and only_blocks[0]["agent_id"] == SECOPS_AGENT_ID

    only_finops = env.timeline(agent_id=FINOPS_AGENT_ID).json()["events"]
    assert len(only_finops) == 3


def test_tenant_isolation_of_the_timeline_and_verify() -> None:
    env = Env()
    env.ingest([_event(FINOPS_AGENT_ID), _event(FINOPS_AGENT_ID)])  # into DEFAULT_ORG_ID
    assert len(env.timeline().json()["events"]) == 2  # the default org's owner sees them

    other = env.client.get("/v1/blackbox/events", headers=env.h_other_org())
    assert other.status_code == 200
    assert other.json()["events"] == []  # OTHER_ORG's owner sees none of DEFAULT_ORG_ID's events

    other_verify = env.client.get(
        "/v1/blackbox/verify", params={"from_seq": 1, "to_seq": 2}, headers=env.h_other_org()
    )
    assert other_verify.json() == {"ok": True, "checked": 0, "broken_seq": None, "reason": None}  # no chain of its own yet

    verify_resp = env.verify(1, 2)
    assert verify_resp.json()["ok"] is True
    assert verify_resp.json()["checked"] == 2


def test_verify_detects_a_tampered_event() -> None:
    env = Env()
    env.ingest([_event(FINOPS_AGENT_ID), _event(FINOPS_AGENT_ID), _event(FINOPS_AGENT_ID)])
    clean = env.verify(1, 3).json()
    assert clean == {"ok": True, "checked": 3, "broken_seq": None, "reason": None}

    # Tamper directly with the store, the way nothing in the real API can.
    tampered = next(e for e in env.store.tables["agent_events"] if e["seq"] == 2)
    tampered["hash"] = "0" * 64

    broken = env.verify(1, 3).json()
    assert broken["ok"] is False
    assert broken["broken_seq"] == 2
    assert broken["reason"] == "hash_mismatch"


def test_verify_rejects_an_oversized_or_inverted_range() -> None:
    env = Env()
    env.ingest([_event(FINOPS_AGENT_ID)])
    assert env.verify(5, 2).status_code == 400
    assert env.verify(1, 1).json()["ok"] is True  # a well-formed small range still works


def test_malformed_items_are_rejected_at_the_schema_boundary() -> None:
    env = Env()
    resp = env.client.post(
        "/internal/v1/events",
        json={"instance_id": INSTANCE, "batch_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID,
              "items": [{"agent_id": FINOPS_AGENT_ID, "decision": "MAYBE", "method": "tools/call",
                         "gateway_instance": INSTANCE, "occurred_at": datetime.now(timezone.utc).isoformat()}]},
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
    )
    assert resp.status_code == 422  # Pydantic rejects an unknown Decision before it reaches record_events


def test_empty_batch_is_rejected() -> None:
    env = Env()
    resp = env.client.post(
        "/internal/v1/events",
        json={"instance_id": INSTANCE, "batch_id": str(uuid4()), "organization_id": DEFAULT_ORG_ID, "items": []},
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
    )
    assert resp.status_code == 422


def test_viewer_role_can_read_the_timeline_and_verify() -> None:
    env = Env()
    env.ingest([_event(FINOPS_AGENT_ID)])
    assert env.timeline(user="viewer").status_code == 200
    assert env.verify(1, 1, user="viewer").status_code == 200


def test_old_timestamp_still_chains_correctly() -> None:
    """occurred_at is the gateway's own clock, which may be seconds behind received_at; this must not
    affect sequencing or chaining, which are store-order, not time-order."""
    env = Env()
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    env.ingest([_event(FINOPS_AGENT_ID, occurred_at=old), _event(FINOPS_AGENT_ID)])
    assert env.verify(1, 2).json()["ok"] is True


# ---------------------------------------------------------------------------
# Retention settings (Phase 3 M2a)
# ---------------------------------------------------------------------------


def _retention(env: Env, user: str = "admin", **body: Any) -> Any:
    return env.client.put("/v1/blackbox/retention", json=body, headers=env.h(user))


def _retention_audit(env: Env) -> list[dict[str, Any]]:
    return [r for r in env.store.tables.get("control_audit_log", []) if r["action"] == "organization.blackbox_retention_changed"]


def test_settings_default_to_30_days_7_days_and_no_payload_capture() -> None:
    env = Env()
    resp = env.client.get("/v1/blackbox/settings", headers=env.h("viewer"))
    assert resp.status_code == 200
    body = resp.json()
    assert body.pop("capabilities")["can_view_payloads"] is False  # a viewer; the role matrix is in test_blackbox_access
    assert body == {"retention_days": 30, "payload_retention_days": 7, "payload_capture_enabled": False, "changed": False}


def test_admin_changes_retention_with_confirmation_and_it_is_audited() -> None:
    env = Env()
    resp = _retention(env, retention_days=14, payload_retention_days=3, reason="keep less", confirm=True)
    assert resp.status_code == 200
    assert resp.json() == {"retention_days": 14, "payload_retention_days": 3, "payload_capture_enabled": False, "changed": True, "capabilities": None}
    assert env.client.get("/v1/blackbox/settings", headers=env.h()).json()["retention_days"] == 14
    (audit,) = _retention_audit(env)
    assert audit["actor_user_id"] == "00000000-0000-0000-0000-0000000000a2"  # the admin, not a client-supplied id
    assert audit["details"]["old_retention_days"] == 30 and audit["details"]["new_retention_days"] == 14


def test_a_retention_change_without_confirmation_is_refused_and_changes_nothing() -> None:
    env = Env()
    resp = _retention(env, user="owner", retention_days=7, payload_retention_days=7)
    assert resp.status_code == 400
    assert "confirm" in resp.json()["detail"]
    assert env.client.get("/v1/blackbox/settings", headers=env.h()).json()["retention_days"] == 30
    assert _retention_audit(env) == []


def test_resending_the_current_values_needs_no_confirmation_and_is_not_audited() -> None:
    env = Env()
    resp = _retention(env, retention_days=30, payload_retention_days=7)
    assert resp.status_code == 200 and resp.json()["changed"] is False
    assert _retention_audit(env) == []


def test_only_admins_and_owners_can_change_retention() -> None:
    env = Env()
    for user in ("viewer", "operator"):
        resp = _retention(env, user=user, retention_days=14, payload_retention_days=3, confirm=True)
        assert resp.status_code == 403, user
    assert _retention_audit(env) == []


def test_retention_outside_the_allowed_ranges_is_rejected() -> None:
    env = Env()
    for body in (
        {"retention_days": 6, "payload_retention_days": 7},
        {"retention_days": 91, "payload_retention_days": 7},
        {"retention_days": 30, "payload_retention_days": 0},
        {"retention_days": 30, "payload_retention_days": 31},
        {"retention_days": "30", "payload_retention_days": 7},
        {"retention_days": 30},
        {"retention_days": 30, "payload_retention_days": 7, "payload_capture_enabled": True},
    ):
        resp = _retention(env, confirm=True, **body)
        assert resp.status_code == 422, body
    assert _retention_audit(env) == []


def test_retention_changes_stay_within_the_callers_organization() -> None:
    env = Env()
    resp = env.client.put(
        "/v1/blackbox/retention", headers=env.h_other_org(),
        json={"retention_days": 7, "payload_retention_days": 1, "confirm": True},
    )
    assert resp.status_code == 200
    assert env.client.get("/v1/blackbox/settings", headers=env.h_other_org()).json()["retention_days"] == 7
    assert env.client.get("/v1/blackbox/settings", headers=env.h()).json()["retention_days"] == 30


# ---------------------------------------------------------------------------
# Payload capture (Phase 3 M2b)
# ---------------------------------------------------------------------------


def _excerpt(text: str = "{\"path\":\"/tmp/a\"}", truncated: bool = False) -> dict[str, Any]:
    return {"text": text, "truncated": truncated, "original_bytes": len(text.encode())}


def _capture(env: Env, user: str = "admin", **body: Any) -> Any:
    return env.client.put("/v1/blackbox/payload-capture", json=body, headers=env.h(user))


def _capture_audit(env: Env) -> list[dict[str, Any]]:
    return [r for r in env.store.tables.get("control_audit_log", []) if r["action"] == "organization.payload_capture_changed"]


def _stored(env: Env, seq: int = 1) -> dict[str, Any]:
    return next(
        e for e in env.store.tables["agent_events"] if e["organization_id"] == DEFAULT_ORG_ID and e["seq"] == seq
    )


def test_payloads_are_dropped_while_capture_is_off() -> None:
    env = Env()
    resp = env.ingest([_event(FINOPS_AGENT_ID, arguments_redacted=_excerpt(), result_excerpt=_excerpt("ok"))])
    assert resp.json() == {"accepted": 1, "rejected": 0}  # the event is kept, the payload is not
    stored = _stored(env)
    assert stored["arguments_redacted"] is None and stored["result_excerpt"] is None


def test_payloads_are_stored_once_capture_is_on() -> None:
    env = Env()
    assert _capture(env, enabled=True, confirm=True).status_code == 200
    env.ingest([_event(FINOPS_AGENT_ID, arguments_redacted=_excerpt(), result_excerpt=_excerpt("ok"))])
    stored = _stored(env)
    assert stored["arguments_redacted"]["text"] == "{\"path\":\"/tmp/a\"}"
    assert stored["result_excerpt"] == _excerpt("ok")
    assert env.verify(1, 1).json()["ok"] is True  # the hash does not cover the payload


def test_the_timeline_never_returns_payloads() -> None:
    env = Env()
    _capture(env, enabled=True, confirm=True)
    env.ingest([_event(FINOPS_AGENT_ID, arguments_redacted=_excerpt("distinctive-payload-text"))])
    body = env.timeline().text
    assert "distinctive-payload-text" not in body and "arguments_redacted" not in body


def test_malformed_payloads_are_rejected_at_the_schema_boundary() -> None:
    env = Env()
    _capture(env, enabled=True, confirm=True)
    for bad in (
        {"text": "x" * 2049, "truncated": False, "original_bytes": 2049},
        {"text": "x", "truncated": "no", "original_bytes": 1},
        {"text": "x", "truncated": False, "original_bytes": -1},
        {"text": "x", "truncated": False, "original_bytes": 1, "extra": 1},
        {"truncated": False, "original_bytes": 1},
        "just a string",
    ):
        resp = env.ingest([_event(FINOPS_AGENT_ID, arguments_redacted=bad)])
        assert resp.status_code == 422, bad
    assert env.store.tables.get("agent_events", []) == []


def test_admin_turns_capture_on_with_confirmation_and_it_is_audited() -> None:
    env = Env()
    resp = _capture(env, enabled=True, confirm=True, reason="debugging an agent")
    assert resp.status_code == 200
    assert resp.json()["payload_capture_enabled"] is True and resp.json()["changed"] is True
    assert env.client.get("/v1/blackbox/settings", headers=env.h()).json()["payload_capture_enabled"] is True
    (audit,) = _capture_audit(env)
    assert audit["actor_user_id"] == "00000000-0000-0000-0000-0000000000a2"
    assert audit["details"] == {"old_enabled": False, "new_enabled": True}


def test_turning_capture_on_without_confirmation_is_refused() -> None:
    env = Env()
    resp = _capture(env, enabled=True)
    assert resp.status_code == 400 and "confirm" in resp.json()["detail"]
    assert env.client.get("/v1/blackbox/settings", headers=env.h()).json()["payload_capture_enabled"] is False
    assert _capture_audit(env) == []


def test_only_admins_can_turn_capture_on() -> None:
    env = Env()
    for user in ("viewer", "operator"):
        assert _capture(env, user=user, enabled=True, confirm=True).status_code == 403, user
    assert _capture_audit(env) == []


def test_a_security_operator_can_turn_capture_off_without_confirmation() -> None:
    env = Env()
    _capture(env, enabled=True, confirm=True)
    resp = _capture(env, user="operator", enabled=False)
    assert resp.status_code == 200 and resp.json()["payload_capture_enabled"] is False
    assert _capture(env, user="viewer", enabled=False).status_code == 403
    assert [a["details"]["new_enabled"] for a in _capture_audit(env)] == [False, True]  # newest first


def test_repeating_the_current_setting_changes_nothing() -> None:
    env = Env()
    resp = _capture(env, enabled=False)
    assert resp.status_code == 200 and resp.json()["changed"] is False
    _capture(env, enabled=True, confirm=True)
    again = _capture(env, enabled=True)  # already on: no confirmation needed for a no-op
    assert again.status_code == 200 and again.json()["changed"] is False
    assert len(_capture_audit(env)) == 1


def test_capture_settings_are_per_organization() -> None:
    env = Env()
    _capture(env, enabled=True, confirm=True)
    assert env.client.get("/v1/blackbox/settings", headers=env.h_other_org()).json()["payload_capture_enabled"] is False
    other = env.client.put(
        "/v1/blackbox/payload-capture", json={"enabled": True, "confirm": True}, headers=env.h_other_org()
    )
    assert other.status_code == 200
    assert len(_capture_audit(env)) == 2


def test_payload_capture_rejects_unknown_fields_and_non_booleans() -> None:
    env = Env()
    assert _capture(env, enabled="yes", confirm=True).status_code == 422
    assert _capture(env, enabled=True, confirm=True, retention_days=7).status_code == 422
    assert _capture(env).status_code == 422


def test_the_gateway_context_says_whether_to_capture() -> None:
    env = Env()
    headers = {"Authorization": f"Bearer {SERVICE_TOKEN}"}
    params = {"agent_id": FINOPS_AGENT_ID, "organization_id": DEFAULT_ORG_ID, "server": "xero", "instance_id": INSTANCE}
    assert env.client.get("/internal/v1/gateway-context", params=params, headers=headers).json()["agent"]["payload_capture"] is False
    _capture(env, enabled=True, confirm=True)
    assert env.client.get("/internal/v1/gateway-context", params=params, headers=headers).json()["agent"]["payload_capture"] is True


def test_anything_but_an_explicit_true_means_no_capture_in_the_context() -> None:
    env = Env()
    headers = {"Authorization": f"Bearer {SERVICE_TOKEN}"}
    params = {"agent_id": FINOPS_AGENT_ID, "organization_id": DEFAULT_ORG_ID, "server": "xero", "instance_id": INSTANCE}
    org = next(o for o in env.store.tables["organizations"] if o["id"] == DEFAULT_ORG_ID)
    for odd in ("true", 1, None, "yes"):
        org["payload_capture_enabled"] = odd
        assert env.client.get("/internal/v1/gateway-context", params=params, headers=headers).json()["agent"]["payload_capture"] is False, odd
