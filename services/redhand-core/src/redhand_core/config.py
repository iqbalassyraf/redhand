"""
RedHand Core - Application Configuration & Environment Settings
File: services/redhand-core/src/redhand_core/config.py

Manages environment variables and runtime configuration for `redhand-core`
using Pydantic `BaseSettings`.
"""

from __future__ import annotations

from functools import lru_cache
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
            "HS256 mode: the shared secret that signs operator access tokens (a Supabase "
            "project still on its legacy JWT secret, and local development). In "
            "development/test a random per-process secret is generated when unset. "
            "Mutually exclusive with OPERATOR_JWKS_URL."
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
    AGENT_TOKEN_TTL_SECONDS: int = Field(default=600, ge=60, le=900)
    AGENT_TOKEN_EXCHANGES_PER_MINUTE: int = Field(default=30, ge=1, le=600)
    INTERNAL_SERVICE_TOKEN: SecretStr | None = Field(
        default=None,
        description=(
            "Shared secret the gateway (AgentWall) presents on /internal endpoints. When "
            "unset, those endpoints reject every call, so the gateway denies all traffic."
        ),
    )
    ALLOW_INSECURE_MCP_URLS: bool = Field(
        default=False,
        description="Development only: allow http:// and localhost MCP server URLs.",
    )

    @model_validator(mode="after")
    def _operator_auth_mode(self) -> Settings:
        """Exactly one operator verification mode; refuse to start otherwise (fail closed)."""
        local = self.ENVIRONMENT in ("development", "test")
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
        elif self.OPERATOR_JWT_SECRET is None:
            if not local:
                raise ValueError(
                    "Operator authentication is not configured: set OPERATOR_JWKS_URL (and "
                    "OPERATOR_JWT_ISSUER) or OPERATOR_JWT_SECRET."
                )
            self.OPERATOR_JWT_SECRET = SecretStr(secrets.token_urlsafe(32))
        return self

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

