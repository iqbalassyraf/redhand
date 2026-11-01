"""
Ephemeral Token Manager: Orchestrates Just-In-Time credential exchange across providers.
Supports AWS STS, Azure Entra ID, GCP STS, SaaS tokens (GitHub, Slack, Google Workspace), and HashiCorp Vault.
"""

from typing import Any
import structlog
from .providers.base import BaseSTSProvider, EphemeralToken
from .providers.aws_sts import AWSSTSProvider
from .providers.azure_sts import AzureSTSProvider
from .providers.gcp_sts import GCPSTSProvider
from .providers.local_mock import LocalMockSTSProvider
from .providers.saas_token import SaaSTokenProvider
from .providers.vault import VaultSTSProvider

logger = structlog.get_logger(__name__)


def _local_sts_secret() -> bytes | None:
    # Imported lazily so the broker can be constructed in tests without settings files.
    from ...config.settings import get_settings

    configured = get_settings().LOCAL_STS_SIGNING_SECRET
    return configured.get_secret_value().encode("utf-8") if configured else None


class EphemeralTokenBroker:
    """Zero-Trust Just-In-Time Credential Broker across Multi-Cloud and SaaS Providers."""

    def __init__(self, default_provider: str = "local_sts") -> None:
        self.default_provider = default_provider
        self._providers: dict[str, BaseSTSProvider] = {
            "local_sts": LocalMockSTSProvider(signing_secret=_local_sts_secret()),
            "aws_sts": AWSSTSProvider(),
            "azure_sts": AzureSTSProvider(),
            "gcp_sts": GCPSTSProvider(),
            "saas": SaaSTokenProvider(),
            "vault": VaultSTSProvider(),
        }

    def register_provider(self, name: str, provider: BaseSTSProvider) -> None:
        self._providers[name] = provider

    def get_provider(self, name: str) -> BaseSTSProvider | None:
        return self._providers.get(name)

    async def mint_ephemeral_token(
        self,
        *,
        agent_id: str,
        tool_name: str,
        target_audience: str,
        provider_name: str | None = None,
        ttl_seconds: int = 60,
        user_id: str | None = None,
        user_roles: list[str] | None = None,
        **kwargs: Any,
    ) -> EphemeralToken:
        p_name = provider_name or self.default_provider
        provider = self._providers.get(p_name)
        if not provider:
            logger.warning("Requested unknown provider, falling back to local_sts", requested=p_name)
            provider = self._providers["local_sts"]

        # Enforce strict 60s security upper bound (NIST AI 600-1 / Zero-Trust least privilege)
        effective_ttl = max(5, min(ttl_seconds, 60))

        token = await provider.mint_token(
            agent_id=agent_id,
            tool_name=tool_name,
            target_audience=target_audience,
            ttl_seconds=effective_ttl,
            user_id=user_id,
            user_roles=user_roles,
            **kwargs,
        )

        logger.info(
            "Minted JIT ephemeral token",
            agent_id=agent_id,
            tool_name=tool_name,
            audience=target_audience,
            provider=p_name,
            jti=token.token_jti,
            ttl_seconds=effective_ttl,
            user_id=user_id,
            user_roles=user_roles,
        )
        return token

    async def validate_token(self, token: EphemeralToken) -> bool:
        provider = self._providers.get(token.provider_type)
        if not provider:
            return False
        return await provider.validate_token(token)


_broker_instance: EphemeralTokenBroker | None = None


def get_token_broker() -> EphemeralTokenBroker:
    global _broker_instance
    if _broker_instance is None:
        _broker_instance = EphemeralTokenBroker()
    return _broker_instance
