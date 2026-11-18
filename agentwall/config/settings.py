"""
Environment configuration for AgentWall Zero-Trust Proxy.
"""

from __future__ import annotations

from pathlib import Path
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Environment names where the development-only switches may be on. Anything else (a typo included) is treated as shared.
LOCAL_ENVIRONMENTS = frozenset({"development", "dev", "test", "local"})


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
        default=2.0, ge=0.0, le=2.5,
        description="How long a passport lookup is reused. Capped so that, with a hanging core, the first refusal still comes within 4.5 s (revocation promise: 5 s).",
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
    MODEL_PROXY_ENABLED: bool = Field(
        default=False,
        description="PROTOTYPE (Phase 4.5 B5, ADR 0025). True mounts POST /v1/model/anthropic/v1/messages. Off by default: the route does not exist.",
    )
    MODEL_PROXY_ANTHROPIC_URL: str = Field(default="https://api.anthropic.com", description="Provider base URL for the model proxy prototype.")
    MODEL_PROXY_ANTHROPIC_KEY: SecretStr | None = Field(
        default=None,
        description="The deployment's own provider key, held only in this process and sent only to the provider. Without it the proxy refuses every call.",
    )
    MODEL_PROXY_ALLOWED_MODELS: str = Field(
        default="", description="Comma-separated model ids allowed for the whole deployment; empty means the passport scopes alone decide.",
    )
    MODEL_USAGE_FLUSH_INTERVAL_SECONDS: float = Field(
        default=5.0, ge=0.5, le=60.0,
        description="How often the model proxy reports the usage the provider counted to core (B5b). A daily dollar limit sees new spend only after this, plus core's processing and the passport cache lifetime, so a "
        "shorter interval means less overshoot and more calls to core. Prototype only (ADR 0025).",
    )
    MODEL_PROXY_MAX_TOKENS_CAP: int = Field(default=32_000, ge=1, le=200_000, description="Largest max_tokens a proxied request may ask for.")
    DESTINATION_CHECK_ENABLED: bool = Field(
        default=True,
        description="Kill switch for the destination allowlist (Phase 4 M7). False skips the check entirely, whatever an agent's mode says.",
    )
    TOKEN_VERSION_CHECK_ENABLED: bool = Field(
        default=True,
        description="Kill switch for the stale-token check (H4.1). False accepts a token issued for an older passport version again "
        "(a token from before an unfreeze, or before a scope or expiry change). Status and scopes still decide every call.",
    )
    STRICT_PINNING_ENABLED: bool = Field(
        default=True,
        description="Kill switch for strict tool pinning (H4.2). False judges a tool this gateway process has not seen listed by its approved name "
        "alone again; True fetches the server's tool list on first use and judges the tool's current version (refusing when that cannot be done).",
    )
    REDACT_UPSTREAM_ERRORS_ENABLED: bool = Field(
        default=True,
        description="Kill switch for redacting and bait-checking JSON-RPC errors from an MCP server (H4.3). False passes an upstream error through "
        "untouched again, as before; a secret or a bait value in its message or data then reaches the agent.",
    )
    RADAR_MODEL_ENABLED: bool = Field(
        default=False,
        description="Also run the second-stage injection model in the Radar's background scan (about 8 ms more CPU per large result, never inline).",
    )
    ALLOW_INSECURE_UPSTREAMS: bool = Field(
        default=False,
        description="Development only: allow http:// and private-network MCP server URLs.",
    )
    TRUSTED_PROXY_HOPS: int = Field(
        default=0, ge=0, le=5,
        description="How many proxies the gateway runs behind (Cloud Run: 1). The caller's address is then the X-Forwarded-For entry that many "
        "places from the right; 0 ignores the header. Never set higher than the real number: a caller controls everything to the left.",
    )
    UPSTREAM_PIN_ENABLED: bool = Field(
        default=True,
        description="Connect to the address the destination check approved (closes DNS rebinding). False connects by name again after the "
        "same check: a kill switch for a deployment where pinning misbehaves, not a setting to leave off.",
    )
    UPSTREAM_CONNECT_TIMEOUT_SECONDS: float = Field(default=5.0, gt=0, le=30)
    UPSTREAM_TIMEOUT_SECONDS: float = Field(default=30.0, gt=0, le=120)
    MAX_UPSTREAM_RESPONSE_BYTES: int = Field(default=5 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    MAX_REQUEST_BYTES: int = Field(default=1024 * 1024, ge=1024, le=10 * 1024 * 1024)

    LOG_LEVEL: str = Field(default="INFO", description="Structured logging level")
    OTEL_SERVICE_NAME: str = Field(default="agentwall-proxy", description="OpenTelemetry service name")

    @model_validator(mode="after")
    def _model_proxy_is_local_or_staging_only(self) -> Settings:
        """The model proxy holds ONE deployment-level provider key in an environment variable (ADR 0025): fine for a measured prototype, not for customers' traffic.
        Until per-tenant, envelope-encrypted key custody exists (ADR 0029 draft, CLAUDE.md 5.2) it may only be switched on in a local or staging environment; any other
        value, a typo such as "prod" included, refuses to start (fail closed)."""
        if self.MODEL_PROXY_ENABLED and self.ENVIRONMENT.strip().lower() not in LOCAL_ENVIRONMENTS | {"staging"}:
            raise ValueError(
                "MODEL_PROXY_ENABLED may only be set when ENVIRONMENT is 'development', 'dev', 'test', 'local' or 'staging': "
                "provider-key custody for customer traffic is not built (docs/adr/0025-model-proxy-prototype.md)."
            )
        return self

    @model_validator(mode="after")
    def _insecure_upstreams_are_development_only(self) -> Settings:
        """ALLOW_INSECURE_UPSTREAMS switches off the destination check. Only a name known to be local may use it; any other value, a typo
        such as "prod" included, refuses to start (fail closed)."""
        if self.ALLOW_INSECURE_UPSTREAMS and self.ENVIRONMENT.strip().lower() not in LOCAL_ENVIRONMENTS:
            raise ValueError(
                "ALLOW_INSECURE_UPSTREAMS may only be set when ENVIRONMENT is 'development', 'dev', 'test' or 'local'."
            )
        return self


_settings_instance: Settings | None = None


def get_settings() -> Settings:
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance

