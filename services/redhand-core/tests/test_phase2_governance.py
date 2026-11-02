"""
RedHand Core - Phase 2 Governance & Four-Eyes Unit Tests
File: services/redhand-core/tests/test_phase2_governance.py
"""

from __future__ import annotations

import json
from urllib.parse import urlencode
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from pydantic import SecretStr

from redhand_core.services.local_store import DEV_OPERATORS

from core_helpers import make_client, operator_headers
from redhand_core.services.notifications.slack import (
    build_slack_hitl_blocks,
    parse_slack_interactive_payload,
)
from redhand_core.services.policy_engine import (
    get_policy_engine,
)


def test_policy_engine_rules() -> None:
    engine = get_policy_engine()

    # 1. Non-prod targeting prod is FORBIDDEN (RH-PAC-001)
    d1 = engine.evaluate(
        agent_environment="staging",
        tool_name="delete_table",
        risk_tier="destructive",
        target_resource="//sqladmin.googleapis.com/projects/corp-prod-db/instances/prod01",
    )
    assert not d1.allowed
    assert d1.matched_rule_id == "RH-PAC-001"

    # 2. Production destructive action enforces Four-Eyes (RH-PAC-002)
    d2 = engine.evaluate(
        agent_environment="production",
        tool_name="delete_production_database",
        risk_tier="destructive",
        target_resource="//sqladmin.googleapis.com/projects/prod/instances/inst1",
    )
    assert d2.allowed
    assert d2.requires_hitl
    assert d2.required_approvals == 2
    assert d2.matched_rule_id == "RH-PAC-002"

    # 3. State mutation requires single approval (RH-PAC-003)
    d3 = engine.evaluate(
        agent_environment="production",
        tool_name="update_dns_record",
        risk_tier="state_mutation",
    )
    assert d3.allowed
    assert d3.requires_hitl
    assert d3.required_approvals == 1
    assert d3.matched_rule_id == "RH-PAC-003"

    # 4. Read only requires 0 approvals
    d4 = engine.evaluate(
        agent_environment="production",
        tool_name="inspect_metrics",
        risk_tier="read_only",
    )
    assert d4.allowed
    assert not d4.requires_hitl
    assert d4.required_approvals == 0


def test_slack_block_kit_generation_and_payload_parser() -> None:
    intervention = {
        "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "proposed_tool_name": "delete_production_database",
        "risk_tier": "destructive",
        "agent_name": "FinOps CloudSQL Remediator",
        "target_cloud_resource": "//sqladmin/prod/db01",
        "agent_justification": "Cost optimization test.",
        "proposed_tool_arguments": {"db": "db01"},
        "required_approvals": 2,
        "approvals": [],
    }

    blocks = build_slack_hitl_blocks(intervention)
    assert "blocks" in blocks
    assert len(blocks["blocks"]) >= 4
    # Action buttons present
    action_block = next(b for b in blocks["blocks"] if b["type"] == "actions")
    assert len(action_block["elements"]) == 2
    assert action_block["elements"][0]["action_id"] == "redhand_hitl_approve"
    assert action_block["elements"][1]["action_id"] == "redhand_hitl_deny"

    # Simulate Slack webhook click payload
    slack_payload_dict = {
        "user": {"id": "U12345678", "username": "alice.security"},
        "actions": [
            {
                "action_id": "redhand_hitl_approve",
                "value": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
            }
        ],
    }
    encoded_body = urlencode({"payload": json.dumps(slack_payload_dict)})

    parsed = parse_slack_interactive_payload(encoded_body)
    assert parsed is not None
    assert parsed["intervention_id"] == "7c9e6679-7425-40de-944b-e07fc1f90ae7"
    assert parsed["action"] == "approve"
    assert "alice.security" in parsed["reviewer_comment"]
    # Reviewer ID is mapped to a valid RFC 4122 UUID string
    assert len(parsed["reviewer_user_id"]) == 36


def test_four_eyes_approval_lifecycle_and_slack_webhook(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import AsyncMock
    mock_webhook = AsyncMock()
    monkeypatch.setattr("redhand_core.routers.hitl.trigger_agent_resume_webhook", mock_webhook)

    from redhand_core.services.local_store import DEFAULT_ORG_ID

    client, settings = make_client(
        SLACK_SIGNING_SECRET=SecretStr(TEST_SLACK_SECRET),
        SLACK_ORGANIZATION_ID=DEFAULT_ORG_ID,
    )
    op1_headers = operator_headers("operator", settings)
    op1_id = DEV_OPERATORS["operator"]["id"]

    # 1. Fetch the default seeded intervention (which requires 2 approvals)
    snapshot = client.get("/v1/state/snapshot", headers=op1_headers).json()
    interventions = snapshot.get("hitl_interventions", [])
    assert len(interventions) >= 1
    target_intervention = interventions[0]
    intervention_id = target_intervention["id"]
    assert target_intervention["required_approvals"] == 2
    assert target_intervention["status"] == "pending"

    operator_1_id = op1_id
    operator_2_id = str(uuid4())  # Slack user (deterministic UUID from the signed payload)

    # 2. First operator signs -> status becomes "partially_approved"
    resp1 = client.post(
        f"/v1/hitl/{intervention_id}/resolve",
        json={
            "action": "approve",
            "reviewer_comment": "Operator 1: Code verified against Jira ticket RH-402.",
        },
        headers=op1_headers,
    )
    assert resp1.status_code == 200, resp1.text
    body1 = resp1.json()
    assert body1["status"] == "partially_approved"
    assert body1["current_signatures"] == 1
    assert body1["required_approvals"] == 2
    assert body1["resume_webhook_dispatched"] is False

    # 3. Same operator attempts to sign again -> 400 Bad Request (Four-Eyes violation)
    resp_duplicate = client.post(
        f"/v1/hitl/{intervention_id}/resolve",
        json={
            "action": "approve",
            "reviewer_comment": "Operator 1 signing again.",
        },
        headers=op1_headers,
    )
    assert resp_duplicate.status_code == 400
    assert "Four-Eyes Principle violation" in resp_duplicate.json()["detail"]

    # 4. Second operator signs via Slack Interactivity Webhook -> becomes "approved"
    slack_payload_dict = {
        "user": {"id": operator_2_id, "username": "bob.leadsre"},
        "actions": [
            {
                "action_id": "redhand_hitl_approve",
                "value": intervention_id,
            }
        ],
    }
    encoded_form = urlencode({"payload": json.dumps(slack_payload_dict)})

    slack_resp = client.post(
        "/v1/hitl/slack/interactivity",
        content=encoded_form,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            **_slack_signature_headers(TEST_SLACK_SECRET, encoded_form.encode("utf-8")),
        },
    )
    assert slack_resp.status_code == 200, slack_resp.text
    assert "APPROVED" in slack_resp.json()["text"]

    # 5. Verify in state snapshot that intervention is now "approved"
    snapshot_after = client.get("/v1/state/snapshot", headers=op1_headers).json()
    resolved = next(
        i for i in snapshot_after["hitl_interventions"] if i["id"] == intervention_id
    )
    assert resolved["status"] == "approved"
    assert len(resolved["approvals"]) == 2
    assert resolved["approvals"][0]["reviewer_user_id"] == operator_1_id
    assert resolved["approvals"][1]["reviewer_user_id"] == operator_2_id

    # 6. Verify webhook was dispatched
    mock_webhook.assert_called_once()


# =============================================================================
# Slack request signature verification (fail closed)
# =============================================================================

TEST_SLACK_SECRET = "test-slack-signing-secret"


def _slack_signature_headers(secret: str, body: bytes, timestamp: int | None = None) -> dict[str, str]:
    import hashlib
    import hmac
    import time

    ts = str(timestamp if timestamp is not None else int(time.time()))
    digest = hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    return {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": f"v0={digest}"}


def _slack_client(secret: str | None) -> TestClient:
    from redhand_core.services.local_store import DEFAULT_ORG_ID

    client, _ = make_client(
        SLACK_SIGNING_SECRET=SecretStr(secret) if secret else None,
        SLACK_ORGANIZATION_ID=DEFAULT_ORG_ID,
    )
    return client


_SLACK_FORM = urlencode(
    {
        "payload": json.dumps(
            {
                "user": {"id": "U123", "username": "mallory"},
                "actions": [{"action_id": "redhand_hitl_approve", "value": str(uuid4())}],
            }
        )
    }
)


def test_slack_interactivity_rejected_when_signing_secret_not_configured() -> None:
    resp = _slack_client(None).post(
        "/v1/hitl/slack/interactivity",
        content=_SLACK_FORM,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 503


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Slack-Request-Timestamp": "not-a-number", "X-Slack-Signature": "v0=abc"},
        _slack_signature_headers("wrong-secret", _SLACK_FORM.encode()),
        _slack_signature_headers(TEST_SLACK_SECRET, _SLACK_FORM.encode(), timestamp=1_000_000_000),
    ],
    ids=["missing", "malformed", "wrong-secret", "stale-replay"],
)
def test_slack_interactivity_rejects_bad_signatures(headers: dict[str, str]) -> None:
    resp = _slack_client(TEST_SLACK_SECRET).post(
        "/v1/hitl/slack/interactivity",
        content=_SLACK_FORM,
        headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
    )
    assert resp.status_code == 401


def test_slack_signature_tampered_body_rejected() -> None:
    headers = _slack_signature_headers(TEST_SLACK_SECRET, _SLACK_FORM.encode())
    resp = _slack_client(TEST_SLACK_SECRET).post(
        "/v1/hitl/slack/interactivity",
        content=_SLACK_FORM + "&extra=1",
        headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
    )
    assert resp.status_code == 401
