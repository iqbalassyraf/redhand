"""
Environment configuration for AgentWall Zero-Trust Proxy.
"""

from pathlib import Path
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTWALL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    HOST: str = Field(default="0.0.0.0", description="Bind address for the proxy server")
    PORT: int = Field(default=8080, description="Listening port for AgentWall")
    ENVIRONMENT: str = Field(default="development", description="Runtime environment")
    
    POLICY_FILE_PATH: str = Field(
        default=str(Path(__file__).parent / "policies.yaml"),
        description="Path to YAML policy definitions",
    )
    
    DEFAULT_IAM_PROVIDER: str = Field(
        default="local_sts",
        description="Default provider for minting ephemeral tokens",
    )

    DEFAULT_TOKEN_TTL_SECONDS: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Default JIT ephemeral token lifetime in seconds",
    )
    
    MAX_TOKEN_TTL_SECONDS: int = Field(
        default=60,
        ge=5,
        le=300,
        description="Hard upper bound for JIT ephemeral token lifetimes",
    )
    
    CORS_ALLOWED_ORIGINS: list[str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Browser origins allowed to call the gateway (the dashboard).",
    )

    LOCAL_STS_SIGNING_SECRET: SecretStr | None = Field(
        default=None,
        description=(
            "HMAC secret for the local development token provider. When unset, a random "
            "per-process secret is generated, so tokens never verify across restarts."
        ),
    )


    # ------------------------------------------------------------------
    # Passport enforcement (Phase 1)
    # ------------------------------------------------------------------
    CORE_URL: str = Field(
        default="http://localhost:8000", description="Base URL of redhand-core (internal network)."
    )
    CORE_SERVICE_TOKEN: SecretStr | None = Field(
        default=None,
        description=(
            "Must equal redhand-core's INTERNAL_SERVICE_TOKEN. Without it every agent call is "
            "denied because passports cannot be checked."
        ),
    )
    AGENT_TOKEN_PUBLIC_KEY: str | None = Field(
        default=None,
        description=(
            "Ed25519 public key (PEM) for agent access tokens. When unset, keys are fetched "
            "from core's /v1/agent-auth/jwks."
        ),
    )
    CONTEXT_CACHE_TTL_SECONDS: float = Field(
        default=2.0, ge=0.0, le=4.0,
        description="How long a passport lookup is reused. Bounded to keep revocation within 5 s.",
    )
    ALLOW_INSECURE_UPSTREAMS: bool = Field(
        default=False,
        description="Development only: allow http:// and private-network MCP server URLs.",
    )
    UPSTREAM_CONNECT_TIMEOUT_SECONDS: float = Field(default=5.0, gt=0, le=30)
    UPSTREAM_TIMEOUT_SECONDS: float = Field(default=30.0, gt=0, le=120)
    MAX_UPSTREAM_RESPONSE_BYTES: int = Field(default=5 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    MAX_REQUEST_BYTES: int = Field(default=1024 * 1024, ge=1024, le=10 * 1024 * 1024)

    LOG_LEVEL: str = Field(default="INFO", description="Structured logging level")
    OTEL_SERVICE_NAME: str = Field(default="agentwall-proxy", description="OpenTelemetry service name")
    AUDIT_LOG_FILE: str | None = Field(default=None, description="Optional path to append WORM audit records")


_settings_instance: Settings | None = None


def get_settings() -> Settings:
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance

