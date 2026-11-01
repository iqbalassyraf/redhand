"""
Base interface and data models for Ephemeral Token Providers.
"""

from abc import ABC, abstractmethod
import time
from typing import Any
from pydantic import BaseModel, Field


class EphemeralToken(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    token_jti: str
    issued_at: float = Field(default_factory=time.time)
    expires_at: float
    ttl_seconds: int
    target_audience: str
    bound_agent_id: str
    bound_tool_name: str
    provider_type: str
    user_id: str | None = None
    user_roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def is_valid_for(self, target_audience: str, tool_name: str) -> bool:
        if self.is_expired():
            return False
        if self.target_audience != target_audience:
            return False
        if self.bound_tool_name != tool_name:
            return False
        return True


class BaseSTSProvider(ABC):
    """Abstract Base Class for JIT Ephemeral Credential Providers."""

    @abstractmethod
    async def mint_token(
        self,
        *,
        agent_id: str,
        tool_name: str,
        target_audience: str,
        ttl_seconds: int = 60,
        user_id: str | None = None,
        user_roles: list[str] | None = None,
        **kwargs: Any,
    ) -> EphemeralToken:
        """Mints an ephemeral token strictly bound to caller, tool, and target audience."""
        pass

    @abstractmethod
    async def validate_token(self, token: EphemeralToken) -> bool:
        """Validates the cryptographic integrity and expiration of a token."""
        pass
