"""
RedHand Core - Application Configuration & Environment Settings
File: services/redhand-core/src/redhand_core/config.py

Manages environment variables and runtime configuration for `redhand-core`
using Pydantic `BaseSettings`.
"""

from __future__ import annotations

from functools import lru_cache
import re
import secrets
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Production configuration contract for `redhand-core`.
    Reads from environment variables and `.env` files automatically.
    """

    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Service Runtime Settings
    # -------------------------------------------------------------------------
    APP_NAME: str = "RedHand Core Control Plane"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "staging", "production", "test"] = "development"
    HOST: str = Field(default="0.0.0.0", description="Bind address for Uvicorn worker.")
    PORT: int = Field(default=8000, ge=1, le=65535, description="HTTP listen port (Cloud Run).")
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    CORS_ALLOWED_ORIGINS: list[str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Allowed origins for the Next.js RedHand Command Center.",
    )

    # -------------------------------------------------------------------------
    # Supabase Persistence & Realtime Configuration
    # -------------------------------------------------------------------------
    SUPABASE_URL: str = Field(
        default="https://placeholder-project.supabase.co",
        description="Supabase project URL.",
    )
    SUPABASE_SERVICE_ROLE_KEY: SecretStr = Field(
        default=SecretStr("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.placeholder"),
        description="Service Role JWT used by redhand-core to bypass RLS during batch writes.",
    )

    # -------------------------------------------------------------------------
    # Google Cloud STS & ONNX Model Configuration
    # -------------------------------------------------------------------------
    GCP_PROJECT_ID: str = Field(
        default="redhand-security-sandbox",
        description="Target Google Cloud Project ID for STS and Cloud Run telemetry.",
    )
    GOOGLE_APPLICATION_CREDENTIALS: str | None = Field(
        default=None,
        description="Optional path to base Service Account JSON for STS downscoping.",
    )
    REDHAND_ONNX_MODEL_PATH: Path = Field(
        default=Path.home() / ".cache" / "redhand" / "deberta-v3-prompt-injection-int8.onnx",
        description="Filesystem path to INT8-quantized ONNX prompt injection classifier.",
    )

    # -------------------------------------------------------------------------
    # Circuit Breaker & Webhook Timeouts
    # -------------------------------------------------------------------------
    HITL_WEBHOOK_TIMEOUT_SECONDS: float = Field(
        default=10.0,
        ge=1.0,
        le=60.0,
        description="HTTP timeout when firing resume webhooks to wake suspended agents.",
    )
    DEFAULT_HITL_TTL_SECONDS: int = Field(
        default=3600,
        ge=60,
        le=604800,
        description="Default expiration window for pending HITL circuit breaker checkpoints.",
    )

    # -------------------------------------------------------------------------
    # Slack Interactivity
    # -------------------------------------------------------------------------
    SLACK_SIGNING_SECRET: SecretStr | None = Field(
        default=None,
        description=(
            "Slack app signing secret. When unset, the Slack interactivity endpoint "
            "rejects every request (fail closed)."
        ),
    )

    # -------------------------------------------------------------------------
    # Operator Authentication & Tenant-Scoped Integrations
    # -------------------------------------------------------------------------
    OPERATOR_JWT_SECRET: SecretStr | None = Field(
        default=None,
        description=(
            "HS256 mode: the shared secret that signs operator access tokens. Local development and tests only: any other "
            "ENVIRONMENT refuses to start with it set. In development/test a random per-process secret is generated when "
            "unset. Mutually exclusive with OPERATOR_JWKS_URL."
        ),
    )
    OPERATOR_JWKS_URL: str | None = Field(
        default=None,
        description=(
            "JWKS mode: URL of the public keys that verify operator tokens, e.g. "
            "https://<ref>.supabase.co/auth/v1/.well-known/jwks.json (Supabase projects "
            "using asymmetric signing keys). Accepts ES256 and RS256 only. When set, HS256 "
            "tokens are rejected and OPERATOR_JWT_SECRET is ignored."
        ),
    )
    OPERATOR_JWT_ISSUER: str | None = Field(
        default=None,
        description="Required with OPERATOR_JWKS_URL: the `iss` claim operator tokens must carry, "
        "e.g. https://<ref>.supabase.co/auth/v1.",
    )
    OPERATOR_AUTH_PROVIDER: Literal["supabase", "clerk"] = Field(
        default="supabase",
        description=(
            "Who signs operators in (ADR 0032). 'supabase' (default): Supabase Auth tokens, verified with OPERATOR_JWKS_URL or "
            "OPERATOR_JWT_SECRET. 'clerk': Clerk session tokens from the JWT template 'redhand', verified with CLERK_ISSUER and "
            "CLERK_JWKS_URL; a person is mapped to RedHand's own operator id on first use and never matched by e-mail."
        ),
    )
    CLERK_ISSUER: str | None = Field(
        default=None,
        description="Clerk mode: the Clerk instance URL that issues operator tokens (the `iss` claim), e.g. https://<instance>.clerk.accounts.dev.",
    )
    CLERK_JWKS_URL: str | None = Field(
        default=None,
        description="Clerk mode: the instance's public keys. Defaults to CLERK_ISSUER + /.well-known/jwks.json. RS256 only.",
    )
    CLERK_AUDIENCE: str = Field(
        default="redhand-core",
        min_length=1,
        description="Clerk mode: the `aud` claim the JWT template 'redhand' must set; a token minted for anything else is refused.",
    )
    SLACK_ORGANIZATION_ID: str | None = Field(
        default=None,
        description="Organization whose HITL interventions the configured Slack app may resolve.",
    )
    SCIM_BEARER_TOKEN: SecretStr | None = Field(
        default=None,
        description="Bearer token required on /scim/v2 endpoints. Unset disables SCIM.",
    )

    # -------------------------------------------------------------------------
    # Agent Passports, Agent Tokens & Gateway Integration
    # -------------------------------------------------------------------------
    AGENT_TOKEN_SIGNING_KEY: SecretStr | None = Field(
        default=None,
        description=(
            "Ed25519 private key (PEM) that signs agent access tokens. Required outside "
            "development/test; a random per-process key is used there when unset."
        ),
    )
    SIGNUP_MODE: Literal["invite", "closed"] = Field(
        default="invite",
        description="Who may create an organization: 'invite' needs a single-use sign-up code the platform owner issued (default); 'closed' refuses everyone. "
        "Open self-serve sign-up is deliberately not offered yet.",
    )
    SIGNUPS_PER_HOUR_PER_USER: int = Field(default=10, ge=1, le=1000, description="Attempts to create an organization or accept an invite per user per hour.")
    SIGNUPS_PER_HOUR_PER_SOURCE: int = Field(default=30, ge=1, le=10000, description="The same per source address (a stranger guessing codes).")
    AGENT_TOKEN_TTL_SECONDS: int = Field(default=600, ge=60, le=900)
    AGENT_TOKEN_EXCHANGES_PER_MINUTE: int = Field(default=30, ge=1, le=600)
    AGENT_TOKEN_EXCHANGES_PER_MINUTE_PER_SOURCE: int = Field(
        default=300, ge=1, le=6000,
        description="Token exchanges one source address may attempt per minute, whatever keys it presents. Checked before any database read.",
    )
    TRUSTED_PROXY_HOPS: int = Field(
        default=0, ge=0, le=5,
        description="How many proxies core runs behind (Cloud Run: 1). The source address is then the entry that many places from the right of "
        "X-Forwarded-For; 0 ignores the header. Never set higher than the real number: a caller controls everything to the left.",
    )
    INTERNAL_SERVICE_TOKEN: SecretStr | None = Field(
        default=None,
        description=(
            "Shared secret the gateway (AgentWall) presents on /internal endpoints. When "
            "unset, those endpoints reject every call, so the gateway denies all traffic."
        ),
    )
    GATEWAY_URL: str | None = Field(
        default=None,
        description=(
            "Base URL of the AgentWall gateway (for example https://redhand-gateway-xxxx.a.run.app). Used only for the "
            "MCP Scanner's live scan of registered servers; when unset that scan answers 503 and nothing else changes."
        ),
    )
    # -------------------------------------------------------------------------
    # Telegram panic command (Phase 2). Unset token or secret disables the feature.
    # -------------------------------------------------------------------------
    TELEGRAM_BOT_TOKEN: SecretStr | None = Field(
        default=None,
        description="Bot token from @BotFather. Never logged. Unset disables the Telegram feature.",
    )
    TELEGRAM_WEBHOOK_SECRET: SecretStr | None = Field(
        default=None,
        description=(
            "Secret Telegram sends in X-Telegram-Bot-Api-Secret-Token on every webhook call "
            "(32-256 characters: letters, digits, '_' or '-'). Unset disables the webhook."
        ),
    )
    TELEGRAM_BOT_USERNAME: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9_]{3,64}$",
        description="The bot's @username without the @; used to build the one-tap link.",
    )
    TELEGRAM_COMMANDS_PER_MINUTE: int = Field(default=20, ge=1, le=120)

    MAX_REQUEST_BYTES: int = Field(
        default=1024 * 1024, ge=1024, le=16 * 1024 * 1024,
        description="Largest request body core reads on any route, counted as the bytes arrive. Larger is answered 413.",
    )
    MAX_INGEST_REQUEST_BYTES: int = Field(
        default=16 * 1024 * 1024, ge=1024 * 1024, le=64 * 1024 * 1024,
        description="The larger cap for the batched ingest routes (gateway event reports, trace ingest): up to 500 events or 250 spans a call.",
    )

    DASHBOARD_URL: str | None = Field(
        default=None, max_length=200,
        description="The dashboard's address, e.g. https://redhand.example.com. When set, Telegram alerts about one agent end with a link to "
        "that agent's incident view. https only outside development; no credentials, query or fragment.",
    )

    ALLOW_INSECURE_MCP_URLS: bool = Field(
        default=False,
        description="Development only: allow http:// and localhost MCP server URLs.",
    )
    ALLOW_INSECURE_WEBHOOK_URLS: bool = Field(
        default=False,
        description="Development only: allow http:// and localhost webhook URLs (resume, Slack, SIEM). Never set this on staging or production.",
    )

    @model_validator(mode="after")
    def _operator_auth_mode(self) -> Settings:
        """Exactly one operator verification mode; refuse to start otherwise (fail closed)."""
        local = self.ENVIRONMENT in ("development", "test")
        if self.OPERATOR_AUTH_PROVIDER == "clerk":
            if not self.CLERK_ISSUER:
                raise ValueError("OPERATOR_AUTH_PROVIDER=clerk needs CLERK_ISSUER (the Clerk instance URL).")
            self.CLERK_ISSUER = self.CLERK_ISSUER.rstrip("/")
            if not self.CLERK_JWKS_URL:
                self.CLERK_JWKS_URL = f"{self.CLERK_ISSUER}/.well-known/jwks.json"
            if not local and not (self.CLERK_ISSUER.startswith("https://") and self.CLERK_JWKS_URL.startswith("https://")):
                raise ValueError("CLERK_ISSUER and CLERK_JWKS_URL must use https outside development/test.")
            # Clerk mode never accepts Supabase or shared-secret operator tokens.
            self.OPERATOR_JWT_SECRET = None
            self.OPERATOR_JWKS_URL = None
            self.OPERATOR_JWT_ISSUER = None
            return self
        if self.OPERATOR_JWKS_URL:
            if self.OPERATOR_JWT_SECRET is not None and not local:
                raise ValueError(
                    "Set either OPERATOR_JWKS_URL or OPERATOR_JWT_SECRET, not both: the two "
                    "verification modes are mutually exclusive."
                )
            if not self.OPERATOR_JWT_ISSUER:
                raise ValueError("OPERATOR_JWT_ISSUER is required when OPERATOR_JWKS_URL is set.")
            if not local and not self.OPERATOR_JWKS_URL.startswith("https://"):
                raise ValueError("OPERATOR_JWKS_URL must use https outside development/test.")
            self.OPERATOR_JWT_SECRET = None  # JWKS mode never accepts shared-secret tokens
        elif self.OPERATOR_JWT_SECRET is not None:
            if not local:
                # A shared secret both verifies and mints tokens: whoever holds it can sign in as any operator, in any organization.
                raise ValueError(
                    "OPERATOR_JWT_SECRET (HS256 shared-secret operator tokens) is only allowed when ENVIRONMENT is 'development' or "
                    "'test'. Use OPERATOR_JWKS_URL and OPERATOR_JWT_ISSUER (asymmetric signing keys; in Supabase, enable JWT signing keys)."
                )
        elif self.OPERATOR_JWT_SECRET is None:
            if not local:
                raise ValueError(
                    "Operator authentication is not configured: set OPERATOR_JWKS_URL (and "
                    "OPERATOR_JWT_ISSUER) or OPERATOR_JWT_SECRET."
                )
            self.OPERATOR_JWT_SECRET = SecretStr(secrets.token_urlsafe(32))
        return self

    @model_validator(mode="after")
    def _dashboard_url_shape(self) -> Settings:
        """A plain origin (optionally a path) the alerts can link to. It ends up in messages on owners' phones, so nothing that could carry
        a secret or run as script: no credentials, query, fragment or non-http scheme, and https outside development."""
        if self.DASHBOARD_URL is None:
            return self
        from urllib.parse import urlsplit

        parts = urlsplit(self.DASHBOARD_URL)
        local = self.ENVIRONMENT in ("development", "test")
        allowed = ("https", "http") if local else ("https",)
        if parts.scheme not in allowed or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("DASHBOARD_URL must be a plain https address (http only in development), with no credentials, query or fragment.")
        self.DASHBOARD_URL = self.DASHBOARD_URL.rstrip("/")
        return self

    @model_validator(mode="after")
    def _insecure_flags_are_development_only(self) -> Settings:
        """The ALLOW_INSECURE_* switches turn off the checks that stop core calling an internal address. A shared environment that has one set
        (forgotten, or copied from a dev file) refuses to start; it never runs with the check off."""
        if self.ENVIRONMENT in ("development", "test"):
            return self
        on = [
            name for name in ("ALLOW_INSECURE_MCP_URLS", "ALLOW_INSECURE_WEBHOOK_URLS") if getattr(self, name)
        ]
        if on:
            raise ValueError(f"{', '.join(on)} may only be set when ENVIRONMENT is 'development' or 'test'.")
        return self

    @field_validator("TELEGRAM_WEBHOOK_SECRET")
    @classmethod
    def _telegram_secret_shape(cls, v: SecretStr | None) -> SecretStr | None:
        if v is not None and not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", v.get_secret_value()):
            raise ValueError("TELEGRAM_WEBHOOK_SECRET must be 32-256 characters of letters, digits, '_' or '-'.")
        return v

    @property
    def uses_local_store(self) -> bool:
        """True when no real Supabase project is configured."""
        return "placeholder-project.supabase.co" in self.SUPABASE_URL

    @field_validator("SUPABASE_URL")
    @classmethod
    def normalize_supabase_url(cls, v: str) -> str:
        cleaned = v.strip().rstrip("/")
        if not cleaned.startswith(("http://", "https://")):
            raise ValueError("SUPABASE_URL must start with 'http://' or 'https://'.")
        return cleaned


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Returns a cached singleton of the validated application settings."""
    return Settings()

