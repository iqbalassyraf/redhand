"""Request and response shapes for the tenant lifecycle routes. Strict: unknown fields are refused."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DeleteRequest(_Strict):
    # The owner types the organization's address name back (it is not secret; typing it proves they mean this organization).
    confirm_slug: str = Field(min_length=3, max_length=40)


class DeletionStatus(_Strict):
    requested: bool
    requested_at: datetime | None = None
    purge_after: datetime | None = None


class DeletionRequested(DeletionStatus):
    already: bool = False
