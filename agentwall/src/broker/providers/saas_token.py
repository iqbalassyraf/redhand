"""
SaaS Ephemeral Token Provider for GitHub, Slack, and Google Workspace.
Issues scoped, short-lived tokens replacing long-lived API keys.
"""

import time
from typing import Any
from uuid import uuid4
from .base import BaseSTSProvider, EphemeralToken


class SaaSTokenProvider(BaseSTSProvider):
    """
    SaaS Token Provider orchestrating JIT scoped credentials for:
    - GitHub (Fine-grained installation access tokens)
    - Slack (OAuth scoped bot/user tokens)
    - Google Workspace (Domain-wide delegated OAuth tokens)
    """

    SAAS_PREFIXES = {
        "github": "ghs_",
        "slack": "xoxb-ephemeral-",
        "google_workspace": "ya29.gsuite_obo_",
    }

    def __init__(self, default_service: str = "github") -> None:
        self.default_service = default_service

    async def mint_token(
        self,
        *,
        agent_id: str,
        tool_name: str,
        target_audience: str,
        ttl_seconds: int = 60,
        user_id: str | None = None,
        user_roles: list[str] | None = None,
        service_hint: str | None = None,
        **kwargs: Any,
    ) -> EphemeralToken:
        ttl = max(5, min(ttl_seconds, 60))
        now = time.time()
        exp = now + ttl
        token_hash = uuid4().hex

        # Determine SaaS service based on audience or hint
        service = service_hint or "github"
        aud_lower = target_audience.lower()
        if "slack" in aud_lower:
            service = "slack"
        elif "google" in aud_lower or "workspace" in aud_lower:
            service = "google_workspace"
        elif "github" in aud_lower:
            service = "github"

        prefix = self.SAAS_PREFIXES.get(service, "ghs_")
        access_token = f"{prefix}{token_hash}"
        jti = f"rh_saas_{service}_{token_hash[:12]}"

        # Define fine-grained least privilege scope based on service
        if service == "github":
            scopes = ["repo:read", "issues:write", "pull_requests:read"]
        elif service == "slack":
            scopes = ["chat:write", "channels:read"]
        else:
            scopes = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/drive.readonly"]

        return EphemeralToken(
            access_token=access_token,
            token_type="Bearer",
            token_jti=jti,
            issued_at=now,
            expires_at=exp,
            ttl_seconds=ttl,
            target_audience=target_audience,
            bound_agent_id=agent_id,
            bound_tool_name=tool_name,
            provider_type="saas",
            user_id=user_id,
            user_roles=user_roles or [],
            scopes=scopes,
        )

    async def validate_token(self, token: EphemeralToken) -> bool:
        if token.is_expired():
            return False
        return any(token.access_token.startswith(p) for p in self.SAAS_PREFIXES.values())

