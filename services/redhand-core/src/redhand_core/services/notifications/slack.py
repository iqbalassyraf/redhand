"""
RedHand Core - Slack Block Kit & Interactive Webhook Dispatcher
File: services/redhand-core/src/redhand_core/services/notifications/slack.py

Formats and dispatches enterprise Slack Block Kit approval messages for HITL
circuit breaker interventions and parses interactive button clicks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any
from urllib.parse import parse_qs
from uuid import NAMESPACE_DNS, UUID, uuid5


from redhand_core.net.outbound import OutboundBlockedError, OutboundError, insecure_webhooks_allowed, post_json, record_blocked
from redhand_core.services.safe_log import safe_host

logger = logging.getLogger("redhand.core.slack")


def build_slack_hitl_blocks(intervention: dict[str, Any]) -> dict[str, Any]:
    """
    Constructs an interactive Slack Block Kit message with tool details
    and [Approve] / [Deny] buttons.
    """
    intervention_id = str(intervention.get("id", ""))
    tool_name = str(intervention.get("proposed_tool_name", "unknown_tool"))
    risk_tier = str(intervention.get("risk_tier", "destructive")).upper()
    agent_name = str(intervention.get("agent_name") or intervention.get("external_agent_id") or "Agent")
    target_resource = str(intervention.get("target_cloud_resource", "N/A"))
    justification = str(intervention.get("agent_justification", "No justification provided."))
    required_approvals = intervention.get("required_approvals", 1)
    current_signatures = len(intervention.get("approvals", []))

    args_str = json.dumps(intervention.get("proposed_tool_arguments", {}), indent=2)

    return {
        "text": f"🚨 [RedHand HITL Alert] {agent_name} attempted {tool_name}() ({risk_tier})",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 RedHand HITL Alert: Destructive Action Paused",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agent:*\n{agent_name}"},
                    {"type": "mrkdwn", "text": f"*Risk Tier:*\n`{risk_tier}`"},
                    {"type": "mrkdwn", "text": f"*Tool:*\n`{tool_name}()`"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Signatures Needed:*\n{current_signatures} of {required_approvals}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Target Resource:*\n`{target_resource}`\n*Agent Reasoning:*\n>{justification}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Proposed Tool Arguments:*\n```{args_str[:800]}```",
                },
            },
            {
                "type": "actions",
                "block_id": f"hitl_actions_{intervention_id[:8]}",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve & Resume", "emoji": True},
                        "style": "primary",
                        "action_id": "redhand_hitl_approve",
                        "value": intervention_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny Execution", "emoji": True},
                        "style": "danger",
                        "action_id": "redhand_hitl_deny",
                        "value": intervention_id,
                    },
                ],
            },
        ],
    }


async def dispatch_slack_hitl_notification(
    webhook_url: str,
    intervention: dict[str, Any],
) -> bool:
    """Dispatches Block Kit message to enterprise Slack channel via incoming webhook."""
    if not webhook_url:
        return False

    payload = build_slack_hitl_blocks(intervention)
    try:
        resp = await post_json(webhook_url, payload, allow_insecure=insecure_webhooks_allowed(), timeout=5.0)
        resp.raise_for_status()
        logger.info("Dispatched Slack Block Kit notification for intervention %s", intervention.get("id"))
        return True
    except OutboundError as exc:
        # The webhook URL is the credential: log the host and the fixed error wording only (OutboundError never contains the URL).
        if isinstance(exc, OutboundBlockedError):
            record_blocked("slack")
        logger.warning("Failed to dispatch Slack notification to %s: %s", safe_host(webhook_url), exc)
        return False


SLACK_SIGNATURE_MAX_AGE_SECONDS = 300


def verify_slack_signature(
    *,
    signing_secret: str,
    timestamp_header: str | None,
    signature_header: str | None,
    body: bytes,
    now: float,
) -> bool:
    """
    Verifies a Slack request signature (v0 scheme, HMAC-SHA256 over
    `v0:{timestamp}:{body}`) and rejects requests older than five minutes to
    prevent replay. Returns False on any missing or malformed input.
    """
    if not timestamp_header or not signature_header:
        return False
    try:
        timestamp = int(timestamp_header)
    except ValueError:
        return False
    if abs(now - timestamp) > SLACK_SIGNATURE_MAX_AGE_SECONDS:
        return False
    base = b"v0:" + timestamp_header.encode("utf-8") + b":" + body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def parse_slack_interactive_payload(form_body: str) -> dict[str, Any] | None:
    """
    Parses Slack's URL-encoded interactive webhook payload from button clicks.
    """
    parsed_form = parse_qs(form_body)
    raw_payload_list = parsed_form.get("payload")
    if not raw_payload_list:
        return None

    try:
        data = json.loads(raw_payload_list[0])
        actions = data.get("actions", [])
        if not actions:
            return None

        first_action = actions[0]
        action_id = first_action.get("action_id", "")
        intervention_id = first_action.get("value", "")
        decision = "approve" if "approve" in action_id else "deny"

        user = data.get("user", {})
        reviewer_name = user.get("username") or user.get("name") or "slack_operator"
        raw_user_id = str(user.get("id") or "slack_operator")
        try:
            reviewer_id = str(UUID(raw_user_id))
        except ValueError:
            reviewer_id = str(uuid5(NAMESPACE_DNS, f"slack.user.{raw_user_id}"))

        return {
            "intervention_id": intervention_id,
            "action": decision,
            "reviewer_user_id": reviewer_id,
            "reviewer_comment": f"Resolved via Slack interactive button by @{reviewer_name}",
        }
    except Exception as exc:
        logger.error("Failed to parse Slack interactive payload: %s", exc)
        return None
