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
    BUDGET_FLUSH_INTERVAL_SECONDS: float = Field(
        default=5.0, ge=1.0, le=60.0,
        description="How often call counts are reported to core while there are unreported calls.",
    )
    BUDGET_MAX_TRACKED_KEYS: int = Field(
        default=100_000, ge=100, le=10_000_000,
        description="Most (agent, day) counters held in memory. A limited agent that cannot be tracked is refused.",
    )
    RECORDER_FLUSH_INTERVAL_SECONDS: float = Field(
        default=2.0, ge=0.5, le=30.0,
        description="How often buffered Black Box events are reported to core (Phase 3 M1).",
    )
    RECORDER_MAX_BUFFERED_EVENTS: int = Field(
        default=10_000, ge=100, le=1_000_000,
        description="Most events held in memory before new ones are dropped (and counted) instead of blocking calls.",
    )
    RECORDER_MAX_BATCH_SIZE: int = Field(
        default=500, ge=1, le=500,
        description="Most events sent to core in one report call. Must not exceed core's own per-batch limit.",
    )
    LOOP_DETECTION_ENABLED: bool = Field(
        default=True,
        description="Kill switch for loop detection (Phase 4 M6). False skips the meter entirely, whatever the organization's mode says.",
    )
    DESTINATION_CHECK_ENABLED: bool = Field(
        default=True,
        description="Kill switch for the destination allowlist (Phase 4 M7). False skips the check entirely, whatever an agent's mode says.",
    )
    RADAR_MODEL_ENABLED: bool = Field(
        default=False,
        description="Also run the second-stage injection model in the Radar's background scan (about 8 ms more CPU per large result, never inline).",
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

