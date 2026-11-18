"""
Insights (dashboard redesign S2, ADR 0031): one read-only summary of an organization's gateway decisions over a window, for the dashboard's
home page. Only aggregates leave core: decision counts, sizes, latency percentiles, names of agents, servers and tools, and the fixed reason
strings the gateway already writes. Never an argument value, a payload or a captured text.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Window = Literal["1h", "24h", "7d"]

# window -> (seconds, bucket seconds). Mapped here, never taken from the request: a client cannot ask for an unbounded read.
WINDOWS: dict[str, tuple[int, int]] = {"1h": (3600, 300), "24h": (86400, 3600), "7d": (7 * 86400, 6 * 3600)}


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Totals(_Out):
    decisions: int = Field(ge=0)
    allowed: int = Field(ge=0)
    refused: int = Field(ge=0, description="Decision BLOCK: the gateway refused the call.")
    errors: int = Field(ge=0, description="Decision ERROR: the call was allowed but failed to reach or return from the server.")
    bytes_returned: int = Field(ge=0, description="Result bytes returned to agents on allowed calls.")


class SeriesPoint(_Out):
    bucket_start: datetime
    allowed: int = Field(ge=0)
    refused: int = Field(ge=0)
    errors: int = Field(ge=0)
    bytes: int = Field(ge=0)


class AgentRow(_Out):
    agent_id: UUID
    name: str | None = None
    framework: str | None = None
    decisions: int = Field(ge=0)
    refused: int = Field(ge=0)
    errors: int = Field(ge=0)


class ToolRow(_Out):
    server: str
    tool: str
    calls: int = Field(ge=0)
    refused: int = Field(ge=0)


class ServerRow(_Out):
    server: str
    decisions: int = Field(ge=0)
    allowed: int = Field(ge=0)
    refused: int = Field(ge=0)
    errors: int = Field(ge=0)


class ReasonRow(_Out):
    """`reason` is one of a fixed set of categories (agent_not_active, token_stale, honeytoken, safe_mode, out_of_scope, tool_unapproved, daily_limit,
    destination, loop, upstream_error, firewall_rule), never the gateway's raw sentence, which carries tool, server and address names."""

    reason: str
    count: int = Field(ge=0)


class Latency(_Out):
    """The whole call as the gateway saw it, tool time included, over allowed calls only. NOT the gateway's own overhead."""

    samples: int = Field(ge=0)
    p50_ms: float | None = None
    p95_ms: float | None = None


class FlowRow(_Out):
    agent_id: UUID
    server: str
    decision: Literal["ALLOW", "BLOCK", "ERROR"]
    count: int = Field(ge=0)


class Passports(_Out):
    managed_active: int = Field(ge=0)
    frozen: int = Field(ge=0)
    revoked: int = Field(ge=0)
    reported_only: int = Field(ge=0, description="Agents seen only through SDK telemetry: they have no gateway access until promoted.")


class Controls(_Out):
    safe_mode: bool
    radar_mode: Literal["off", "observe", "block"]


class InsightsResponse(_Out):
    window: Window
    window_start: datetime
    window_end: datetime
    bucket_seconds: int
    totals: Totals
    series: list[SeriesPoint]
    agents: list[AgentRow]
    tools: list[ToolRow]
    servers: list[ServerRow]
    reasons: list[ReasonRow]
    latency: Latency
    flow: list[FlowRow]
    passports: Passports
    controls: Controls
