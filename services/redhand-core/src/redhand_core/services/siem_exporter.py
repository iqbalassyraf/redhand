"""
RedHand Core - Async OCSF v1.1.0 SIEM Webhook Exporter
File: services/redhand-core/src/redhand_core/services/siem_exporter.py

Asynchronously ships Open Cybersecurity Schema Framework (OCSF) findings to
enterprise SIEM collectors (Google Chronicle SecOps, Datadog, Splunk HEC)
with exponential backoff and delivery status updates.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger("redhand.core.siem_exporter")


class SIEMExporter:
    """
    Ships OCSF-formatted `security_events` batches to external SIEM webhooks
    off the critical path.
    """

    def __init__(self, max_retries: int = 3, timeout_seconds: float = 5.0) -> None:
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds

    async def export_events(
        self,
        *,
        siem_webhook_url: str,
        security_event_rows: list[dict[str, Any]],
        supabase_client: Any = None,
    ) -> bool:
        if not siem_webhook_url or not security_event_rows:
            return False

        ocsf_batch = [
            row.get("ocsf_payload", row) for row in security_event_rows
        ]
        event_ids = [str(row["id"]) for row in security_event_rows if "id" in row]

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds, connect=2.0)
        ) as client:
            for attempt in range(1, self.max_retries + 1):
                try:
                    resp = await client.post(
                        siem_webhook_url,
                        json={
                            "schema": "ocsf/v1.1.0",
                            "source": "redhand-core",
                            "events": ocsf_batch,
                        },
                        headers={"Content-Type": "application/json"},
                    )
                    resp.raise_for_status()

                    if supabase_client is not None and event_ids:
                        for eid in event_ids:
                            await (
                                supabase_client.table("security_events")
                                .update({"siem_exported": True})
                                .eq("id", eid)
                                .execute()
                            )

                    logger.info(
                        "Exported %d OCSF security findings to SIEM (%s)",
                        len(ocsf_batch),
                        siem_webhook_url,
                    )
                    return True
                except httpx.HTTPError as exc:
                    if attempt == self.max_retries:
                        logger.warning(
                            "SIEM export to %s failed after %d attempts: %s",
                            siem_webhook_url,
                            attempt,
                            exc,
                        )
                        return False
                    await asyncio.sleep(0.25 * (2 ** (attempt - 1)))

        return False


_default_exporter: SIEMExporter | None = None


def get_siem_exporter() -> SIEMExporter:
    global _default_exporter
    if _default_exporter is None:
        _default_exporter = SIEMExporter()
    return _default_exporter

