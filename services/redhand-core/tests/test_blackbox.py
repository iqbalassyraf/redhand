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
        self.store.tables["organizations"].append({"id": OTHER_ORG, "name": "Other", "slug": "other", "safe_mode": False})
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
