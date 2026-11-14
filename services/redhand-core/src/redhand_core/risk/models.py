"""
Models for the Risk Engine (Phase 4.5 B1, ADR 0019). Counts and fixed labels only: nothing here carries a payload, a tool argument or
text the agent wrote.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

from redhand_core.passports.models import MAX_REASON_LENGTH
from redhand_core.risk.scoring import Ladder

RiskLevel = Literal["low", "elevated", "high", "critical"]
Threshold = StrictInt | None  # strict: "50" as text is refused, not quietly turned into 50


class RiskSignalView(BaseModel):
    signal: str
    label: str
    recent: int  # last 24 hours
    older: int  # day 2 to day 7 (counts half)
    points: int
    capped: bool


class RiskWeightView(BaseModel):
    """The published weights, so a person can check the arithmetic on the page."""

    signal: str
    label: str
    points: int
    cap: int


class AgentRiskSummary(BaseModel):
    agent_id: UUID
    name: str
    status: str
    safe_mode: bool
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    action_score: int = Field(ge=0, le=100)  # signals after the last human release only: what the ladder acts on
    reason: str
    released_at: datetime | None = None


class AgentRiskDetail(AgentRiskSummary):
    signals: list[RiskSignalView]
    action_signals: list[RiskSignalView]


class LadderCapabilities(BaseModel):
    can_change: bool


class LadderView(BaseModel):
    alert_at: Threshold
    safe_mode_at: Threshold
    freeze_at: Threshold
    reaching: dict[str, int]  # how many agents' action score reaches each rung right now (shown before an admin turns a rung on)
    reaching_agents: dict[str, list[str]]  # their names, highest score first, at most PREVIEW_NAMES per rung
    capabilities: LadderCapabilities


class RiskListResponse(BaseModel):
    model: str
    agents: list[AgentRiskSummary]
    ladder: LadderView


class BehaviourBacktestView(BaseModel):
    hours: int
    flagged_hours: int
    spike_hours: int
    new_tool_starts: int


class BehaviourView(BaseModel):
    """Phase 4.5 B2, watch only: shown next to the score, never part of it. `status` is "unavailable" when the counts could not be read
    (the score is still shown); every other field is then at its empty value."""

    status: Literal["ok", "unavailable"]
    model: str
    warm: bool = False
    history_days: int = 0
    warmup_days: int
    hour_calls: int = 0
    usual_hourly: float = 0.0
    spike_threshold: int = 0
    spike: bool = False
    new_tools: list[str] = Field(default_factory=list)
    warning: bool = False
    backtest: BehaviourBacktestView | None = None


class RiskDetailResponse(BaseModel):
    model: str
    agent: AgentRiskDetail
    weights: list[RiskWeightView]
    window_days: int = 7
    behaviour: BehaviourView | None = None


class BehaviourSummaryResponse(BaseModel):
    """How noisy the behaviour baseline would be for this organization: counts only, so it can be judged before it is given weight."""

    model: str
    agents: int
    warm_agents: int
    warnings_now: int
    spikes_now: int
    new_tools_now: int
    backtest: BehaviourBacktestView
    flagged_agents: list[str]  # names of agents with a warning now, at most 10


class LadderRequest(BaseModel):
    """A full ladder: send all three rungs. null turns a rung off. Turning Safe Mode or freeze on, or lowering its threshold, makes the
    engine act on agents without a person, so it needs confirm: true."""

    model_config = ConfigDict(extra="forbid")

    alert_at: Threshold = Field(default=None, ge=1, le=100)
    safe_mode_at: Threshold = Field(default=None, ge=1, le=100)
    freeze_at: Threshold = Field(default=None, ge=1, le=100)
    confirm: StrictBool = False
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)

    @model_validator(mode="after")
    def _ordered(self) -> LadderRequest:
        Ladder(self.alert_at, self.safe_mode_at, self.freeze_at)  # raises ValueError -> 422 with the plain message
        return self

    def as_ladder(self) -> Ladder:
        return Ladder(self.alert_at, self.safe_mode_at, self.freeze_at)
