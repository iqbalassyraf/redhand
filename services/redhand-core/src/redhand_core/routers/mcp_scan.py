"""
MCP Scanner, live scan (Phase 4 M2). See docs/plans/phase4-plan.md.

POST /v1/mcp-servers/{server_id}/scan   admin: asks the gateway to list a REGISTERED server's tools and audit them

Core decides who may scan what: the server must be registered, active and in the caller's organization, and its URL
comes from the database, never from the request. The gateway does the fetch (it owns the destination check: https,
public addresses, no redirects, size and time limits) and the audit. The result is not stored; it is returned to the
admin who asked. Everything in the report that came from the server is untrusted, so it is stripped of control
characters and size-capped before it leaves core, and the dashboard shows it as plain text.
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from redhand_core.auth.operator import AdminDep
from redhand_core.config import Settings, get_settings
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.services.metrics import get_metrics

logger = logging.getLogger("redhand.core.mcp_scan")

router = APIRouter(tags=["MCP Scanner"])

SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]

SCAN_TIMEOUT_SECONDS = 30.0
MAX_FINDINGS = 200
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")


def _plain(value: Any, limit: int) -> str:
    """Server-influenced text made safe to show: control and invisible characters removed, length capped."""
    return _CONTROL.sub("", str(value))[:limit]


class ScanFinding(BaseModel):
    id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    category: str
    tool_name: str | None
    title: str
    description: str
    remediation: str


class ScanResponse(BaseModel):
    server_id: UUID
    server_slug: str
    verdict: Literal["PASS", "WARN", "FAIL"]
    risk_score: int = Field(ge=0, le=100)
    tool_count: int
    truncated: bool = Field(description="The server had more tools or pages than the scanner reads; the rest was not scanned.")
    findings: list[ScanFinding]
    findings_omitted: int = Field(description="Findings beyond the first 200, not shown.")
    scanned_at: datetime
    limits: str = Field(
        description="What this scan does not do, shown with the result.",
        default="Static scan of the tool list only: it cannot see what a tool does when called, and a server that requires "
        "credentials to list its tools cannot be scanned.",
    )


async def get_gateway_client(settings: Annotated[Settings, Depends(get_settings)]) -> AsyncIterator[httpx.AsyncClient | None]:
    if not settings.GATEWAY_URL or settings.INTERNAL_SERVICE_TOKEN is None:
        yield None
        return
    async with httpx.AsyncClient(
        base_url=settings.GATEWAY_URL.rstrip("/"), timeout=httpx.Timeout(SCAN_TIMEOUT_SECONDS, connect=3.0), follow_redirects=False
    ) as client:
        yield client


GatewayClientDep = Annotated[httpx.AsyncClient | None, Depends(get_gateway_client)]


@router.post("/v1/mcp-servers/{server_id}/scan", response_model=ScanResponse)
async def scan_registered_server(
    server_id: UUID,
    operator: AdminDep,
    supabase: SupabaseDep,
    gateway: GatewayClientDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScanResponse:
    """Scans one registered, active server of the caller's organization. The result is returned, not stored."""
    rows = list(
        (
            await supabase.table("mcp_servers")
            .select("id,slug,name,url,is_active")
            .eq("id", str(server_id))
            .eq("organization_id", str(operator.organization_id))
            .execute()
        ).data
        or []
    )
    if len(rows) != 1 or rows[0].get("is_active") is not True:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP server not found.")
    server = rows[0]
    if gateway is None or settings.INTERNAL_SERVICE_TOKEN is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Live scanning is not configured.")
    try:
        response = await gateway.post(
            "/internal/v1/scan",
            json={"server_url": server["url"], "server_name": _plain(server["slug"], 128)},
            headers={
                "Authorization": f"Bearer {settings.INTERNAL_SERVICE_TOKEN.get_secret_value()}",
                "X-RedHand-Organization": str(operator.organization_id),  # picks the gateway's per-organization scan budget
            },
        )
    except httpx.HTTPError as exc:
        logger.error("Gateway scan request failed: %s", type(exc).__name__)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "The gateway could not be reached to scan this server.") from None
    if response.status_code == 429:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many scans; try again shortly.")
    if response.status_code == 401:
        logger.error("Gateway refused core's service token for a scan")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Live scanning is misconfigured.")
    if response.status_code == 502:
        detail = _plain(response.json().get("detail", "") if response.headers.get("content-type", "").startswith("application/json") else "", 200)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"The server could not be scanned: {detail or 'it did not answer.'}")
    if response.status_code != 200:
        logger.error("Gateway scan answered HTTP %s", response.status_code)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "The scan could not be completed.")
    try:
        body = response.json()
        report = body["report"]
        findings = [
            ScanFinding(
                id=_plain(f["id"], 32), severity=f["severity"], category=_plain(f["category"], 40),
                tool_name=_plain(f["tool_name"], 128) if f.get("tool_name") is not None else None,
                title=_plain(f["title"], 200), description=_plain(f["description"], 400), remediation=_plain(f["remediation"], 300),
            )
            for f in report["findings"][:MAX_FINDINGS]
        ]
        result = ScanResponse(
            server_id=server_id, server_slug=_plain(server["slug"], 128), verdict=report["verdict"], risk_score=int(report["risk_score"]),
            tool_count=int(body["tool_count"]), truncated=bool(body["truncated"]), findings=findings,
            findings_omitted=max(0, len(report["findings"]) - MAX_FINDINGS), scanned_at=datetime.now(timezone.utc),
        )
    except (KeyError, TypeError, ValueError):
        logger.error("Gateway scan returned an unreadable report")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "The scan result could not be read.") from None
    get_metrics().increment_counter("redhand_mcp_scans_total", labels={"verdict": result.verdict})
    logger.info("MCP scan: organization=%s server=%s verdict=%s findings=%d", operator.organization_id, server["slug"], result.verdict, len(findings))
    return result
