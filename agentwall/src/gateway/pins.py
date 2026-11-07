"""
Tool pinning in the gateway (Phase 4 M3, docs/adr/0014-tool-pinning.md): hashes the tools a server lists, remembers which
versions it has already reported, and reports new ones to core without ever blocking or breaking a call.

A tool version is identified by the SHA-256 of its canonical name, description and input schema. In enforce mode the gateway
shows an agent only tools whose current version the owner approved, and refuses calls to the others. Everything a server says
about a tool is untrusted: it is size-capped before it leaves here, and core stores it only for the owner's review.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
from typing import Any, Protocol
from uuid import UUID

import httpx
import structlog

from ..firewall.description_rules import scan_description
from .dispatch import SHUTDOWN_WAIT_SECONDS, Outcome, ReportDispatcher, outcome_for_status
from .metrics import GatewayMetrics

logger = structlog.get_logger(__name__)

MAX_TRACKED = 20_000
MAX_REPORT_TOOLS = 200
MAX_DESCRIPTION_CHARS = 2000
MAX_SCHEMA_CHARS = 8000
MAX_IN_FLIGHT = 20
RETRY_DELAYS = (0.5, 1.0, 2.0, 4.0)

__all__ = ["MAX_IN_FLIGHT", "Outcome", "PinCoordinator", "PinReport", "PinReporter", "HttpPinReporter", "tool_digest"]


def tool_digest(tool: dict[str, Any]) -> str:
    """Hash of what makes this tool version: its name, description and input schema (canonical JSON)."""
    canonical = json.dumps(
        {"name": tool.get("name"), "description": tool.get("description") or "", "inputSchema": tool.get("inputSchema") or {}},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _observed(tool: dict[str, Any], digest: str) -> dict[str, Any]:
    raw_description = tool.get("description")
    description: str = raw_description if isinstance(raw_description, str) else ""
    try:
        schema = json.dumps(tool.get("inputSchema") or {}, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        schema = ""
    return {
        "name": str(tool["name"])[:128], "digest": digest, "description": description[:MAX_DESCRIPTION_CHARS],
        "schema": schema[:MAX_SCHEMA_CHARS], "rules": [r.rule_id for r in scan_description(description)],
    }


@dataclass(frozen=True, slots=True)
class PinReport:
    organization_id: UUID
    server: str
    tools: tuple[dict[str, Any], ...]


class PinReporter(Protocol):
    async def send(self, report: PinReport) -> Outcome: ...


class HttpPinReporter:
    def __init__(self, *, core_url: str, service_token: str | None, http_client: httpx.AsyncClient | None = None) -> None:
        self._url = core_url.rstrip("/") + "/internal/v1/tool-observations"
        self._token = service_token
        self._http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0))

    async def send(self, report: PinReport) -> Outcome:
        if not self._token:
            return "drop"
        try:
            response = await self._http.post(
                self._url, headers={"Authorization": f"Bearer {self._token}"},
                json={"organization_id": str(report.organization_id), "server": report.server, "tools": list(report.tools)},
            )
        except httpx.HTTPError as exc:
            logger.warning("Tool report failed: core unreachable", error_type=type(exc).__name__)
            return "retry"
        if response.status_code != 200:
            logger.warning("Tool report refused", status=response.status_code)
        return outcome_for_status(response.status_code)


class PinCoordinator:
    """Memory of what this process has seen and reported, plus the non-blocking reporter. All state is bounded."""

    def __init__(
        self, *, reporter: PinReporter, metrics: GatewayMetrics | None = None, retry_delays: tuple[float, ...] = RETRY_DELAYS,
    ) -> None:
        self._reporter = reporter
        self._metrics = metrics
        self._reported: OrderedDict[tuple[UUID, str, str, str], None] = OrderedDict()
        self._observed: OrderedDict[tuple[UUID, str, str], str] = OrderedDict()
        # A report that could not be sent is forgotten, so the next listing of the same tools reports it again.
        self._dispatcher: ReportDispatcher[PinReport] = ReportDispatcher(
            name="tool", send=lambda report: self._reporter.send(report), count=self._count, retry_delays=retry_delays,
            max_in_flight=lambda: MAX_IN_FLIGHT, on_failed=self._forget,
        )

    @property
    def _tasks(self) -> set[Any]:
        return self._dispatcher.tasks

    # -- what the gateway has seen --------------------------------------------------------------------------
    def last_digest(self, organization_id: UUID, server: str, tool: str) -> str | None:
        return self._observed.get((organization_id, server, tool))

    def observe(self, organization_id: UUID, server: str, tools: list[dict[str, Any]]) -> dict[str, str]:
        """Records the current version of every listed tool and reports the versions not yet reported. Returns name -> digest."""
        digests: dict[str, str] = {}
        fresh: list[dict[str, Any]] = []
        for tool in tools:
            digest = tool_digest(tool)
            name = str(tool["name"])
            digests[name] = digest
            self._remember(self._observed, (organization_id, server, name), digest)
            key = (organization_id, server, name, digest)
            if key not in self._reported:
                self._remember(self._reported, key, None)
                if len(fresh) < MAX_REPORT_TOOLS:
                    fresh.append(_observed(tool, digest))
        if fresh:
            self._dispatch(PinReport(organization_id, server, tuple(fresh)))
        return digests

    @staticmethod
    def _remember(store: OrderedDict[Any, Any], key: Any, value: Any) -> None:
        store[key] = value
        store.move_to_end(key)
        while len(store) > MAX_TRACKED:
            store.popitem(last=False)

    # -- reporting ---------------------------------------------------------------------------------------
    def _dispatch(self, report: PinReport) -> None:
        if not self._dispatcher.submit(report):
            self._forget(report)  # try again at the next listing rather than lose it

    def _forget(self, report: PinReport) -> None:
        for tool in report.tools:
            self._reported.pop((report.organization_id, report.server, tool["name"], tool["digest"]), None)

    async def wait_idle(self) -> None:
        await self._dispatcher.wait_idle()

    async def aclose(self, timeout: float = SHUTDOWN_WAIT_SECONDS) -> None:
        await self._dispatcher.aclose(timeout)

    def _count(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_pin_report(outcome)
