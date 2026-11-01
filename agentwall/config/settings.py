"""
Environment configuration for AgentWall Zero-Trust Proxy.
"""

from pathlib import Path
from pydantic import Field
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
    
    FAIL_MODE: str = Field(
        default="fail_closed",
        description="Fallback mode on unhandled error: 'fail_closed' or 'fail_open'",
    )
    
    LOG_LEVEL: str = Field(default="INFO", description="Structured logging level")
    OTEL_SERVICE_NAME: str = Field(default="agentwall-proxy", description="OpenTelemetry service name")
    AUDIT_LOG_FILE: str | None = Field(default=None, description="Optional path to append WORM audit records")


_settings_instance: Settings | None = None


def get_settings() -> Settings:
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance

