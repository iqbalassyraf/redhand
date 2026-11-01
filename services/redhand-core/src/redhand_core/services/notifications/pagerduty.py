"""
RedHand Core - PagerDuty Events API v2 Incident Dispatcher
File: services/redhand-core/src/redhand_core/services/notifications/pagerduty.py

Triggers enterprise high-urgency security incidents to PagerDuty when:
1. An autonomous agent is quarantined due to policy violations.
2. A critical direct/indirect prompt injection attack is detected.
3. A Four-Eyes HITL approval is denied due to suspected malicious intent.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any

import httpx

logger = logging.getLogger("redhand.core.pagerduty")

PAGERDUTY_EVENTS_API_URL = "https://events.pagerduty.com/v2/enqueue"


async def dispatch_pagerduty_alert(
    *,
    routing_key: str,
    summary: str,
    severity: str = "error",  # info, warning, error, critical
    source: str = "redhand-aspm-core",
    agent_id: str | None = None,
    details: dict[str, Any] | None = None,
    dedup_key: str | None = None,
) -> bool:
    """
    Asynchronously fires an incident event to PagerDuty Events API v2.
    """
    if not routing_key or routing_key.startswith("mock_"):
        logger.info(
            "Mock PagerDuty alert dispatched: summary='%s', severity='%s'",
            summary,
            severity,
        )
        return True

    payload: dict[str, Any] = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "severity": severity,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": "Agentic Security Posture Management",
            "group": "SecOps",
            "custom_details": {
                **(details or {}),
                "agent_id": agent_id,
                "platform": "RedHand Zero-Trust ASPM",
            },
        },
    }
    if dedup_key:
        payload["dedup_key"] = dedup_key

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
            resp = await client.post(PAGERDUTY_EVENTS_API_URL, json=payload)
            resp.raise_for_status()
            logger.info("Successfully enqueued PagerDuty incident: %s", summary)
            return True
    except httpx.HTTPError as exc:
        logger.error("Failed to enqueue PagerDuty incident: %s", exc)
        return False

