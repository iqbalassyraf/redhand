"""Request and response models for the approved-models API (Phase 4.5 B4b). Names are plain: letters, digits and . _ : / - only."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, field_validator

from redhand_core.passports.models import MAX_REASON_LENGTH

MAX_APPROVED_MODELS = 50
PROVIDER_PATTERN = r"^[a-z0-9][a-z0-9_.:/-]{0,63}$"
MODEL_PATTERN = r"^[a-z0-9][a-z0-9_.:/-]{0,127}$"


def _normalize(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


class ApprovedModel(BaseModel):
    """One approved (provider, model). Trimmed and lower-cased, so spelling does not matter."""

    model_config = ConfigDict(extra="forbid")

    provider: StrictStr = Field(pattern=PROVIDER_PATTERN)
    model: StrictStr = Field(pattern=MODEL_PATTERN)

    @field_validator("provider", "model", mode="before")
    @classmethod
    def _clean(cls, value: Any) -> Any:
        return _normalize(value)


class ApprovedModelsRequest(BaseModel):
    """Replaces the organization's whole list. `version` is the version the caller read: a changed list is refused (409), not overwritten."""

    model_config = ConfigDict(extra="forbid")

    items: list[ApprovedModel] = Field(max_length=MAX_APPROVED_MODELS)
    version: StrictInt = Field(ge=0)
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(default=False, description="Required to clear the list, which turns the check off.")


class ApprovedModelsResponse(BaseModel):
    items: list[ApprovedModel]
    version: int
    check_active: bool  # False: no list, so nothing is flagged
    max_items: int = MAX_APPROVED_MODELS
    changed: bool = False
