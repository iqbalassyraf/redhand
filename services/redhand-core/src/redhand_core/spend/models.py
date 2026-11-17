"""Request and response models for the model-spend API (Phase 4.5 B4a). Every field that holds a dollar figure is an estimate: see prices.py."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, StrictInt

MAX_REASON_LENGTH = 500
SPEND_LIMIT_MAX_MICRO_USD = 10**12  # $1,000,000 a day; the database refuses more


class SpendLimitRequest(BaseModel):
    """Set an agent's daily estimated-spend limit in micro-dollars (1 = $0.000001); null removes it. It only raises an alert."""

    model_config = ConfigDict(extra="forbid")

    spend_limit_micro_usd: StrictInt | None = Field(default=None, ge=1, le=SPEND_LIMIT_MAX_MICRO_USD)
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required to raise or remove a limit.")


class SpendLimitResponse(BaseModel):
    agent_id: UUID
    spend_limit_micro_usd: int | None
    changed: bool


class ModelUseView(BaseModel):
    """One model's reported use. `provider` and `model` are what the SDK sent (untrusted text, at most 64 and 128 characters)."""

    provider: str
    model: str
    calls: int
    prompt_tokens: int
    completion_tokens: int
    price_known: bool
    estimated_micro_usd: int | None  # None when the price is unknown: never 0
    estimated_text: str | None
    lower_bound: bool  # a tiered model: the real cost may be higher


class MeasuredSpendView(BaseModel):
    """What the model proxy measured for one agent today, from the provider's own token counts. Kept apart from the SDK-reported figures and never added to them."""

    calls: int
    calls_without_usage: int  # calls the provider reported no usage for: not "free", just not counted
    prompt_tokens: int
    completion_tokens: int
    estimated_micro_usd: int  # priced usage only: see unpriced_tokens for the rest
    estimated_text: str
    lower_bound: bool
    unpriced_tokens: int
    unpriced_models: list[str]
    models: list[ModelUseView]


class AgentSpendView(BaseModel):
    agent_id: UUID
    name: str
    status: str
    usage_reported: bool  # False: the agent's SDK reported no model use for this period (not "it cost nothing")
    calls: int
    prompt_tokens: int
    completion_tokens: int
    estimated_micro_usd: int  # priced usage only: see unpriced_tokens for the rest
    estimated_text: str
    lower_bound: bool
    unpriced_tokens: int
    unpriced_models: list[str]
    spend_limit_micro_usd: int | None
    spend_limit_text: str | None
    percent_of_limit: int | None
    models: list[ModelUseView]
    measured: MeasuredSpendView | None = None  # None: the proxy measured nothing for this agent today (or it could not be read: see measured_unavailable)
    measured_unavailable: bool = False  # True: the measured read failed; the reported figures above are still shown


class SpendTodayResponse(BaseModel):
    day: date
    resets_at: datetime
    utc_offset_minutes: int
    currency: Literal["USD"] = "USD"
    prices_as_of: str
    basis: str
    agents: list[AgentSpendView]


class DaySpendView(BaseModel):
    day: date
    usage_reported: bool
    calls: int
    estimated_micro_usd: int
    estimated_text: str
    lower_bound: bool
    unpriced_tokens: int
    models: list[ModelUseView]


class AgentSpendDetailResponse(BaseModel):
    currency: Literal["USD"] = "USD"
    prices_as_of: str
    basis: str
    agent: AgentSpendView  # today
    days: list[DaySpendView]  # the last 7 days, oldest first, empty days kept


# --- what the gateway reports (internal route, service token only) -----------------------------------------------------------------------

MAX_BATCH_ITEMS = 500


class ModelUsageItem(BaseModel):
    """One aggregate of proxied calls. There is no organization field: the agent's own row decides the tenant."""

    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    provider: str = Field(max_length=64)
    model: str = Field(min_length=1, max_length=128)
    calls: StrictInt = Field(ge=1, le=10**6)
    input_tokens: StrictInt = Field(ge=0, le=10**12)
    output_tokens: StrictInt = Field(ge=0, le=10**12)
    calls_without_usage: StrictInt = Field(default=0, ge=0, le=10**6)
    occurred_at: AwareDatetime


class ModelUsageBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    batch_id: UUID
    items: list[ModelUsageItem] = Field(max_length=MAX_BATCH_ITEMS)


class ModelUsageBatchResponse(BaseModel):
    accepted: int
    rejected: int
    duplicate: bool


class GatewayModelSpend(BaseModel):
    """What the model proxy needs to refuse over a daily dollar limit (B5c). Only for the lookup of server "model" and only when the agent HAS a limit. `measured_micro_usd` is priced
    MEASURED usage only (what the SDK reports is never used to refuse); `spend_known` is False when some of today's measured tokens belong to a model with no known price; `priced_models`
    are the Anthropic model ids the price table knows (a trailing -YYYYMMDD stamp is ignored, as in spend/prices.py)."""

    limit_micro_usd: int
    measured_micro_usd: int
    spend_known: bool
    priced_models: list[str]
