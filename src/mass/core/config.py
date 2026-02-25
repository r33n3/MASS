"""Configuration management for MASS.

Uses Pydantic Settings for environment-based configuration with
sensible defaults for development and production.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database connection settings.

    Supports:
    - PostgreSQL: postgresql+asyncpg://user:pass@host:port/db
    - SQLite: sqlite+aiosqlite:///path/to/db.db
    """

    model_config = SettingsConfigDict(env_prefix="MASS_DB_")

    url: str = Field(
        default="postgresql+asyncpg://mass:mass@localhost:5432/mass",
        description="Database connection URL",
    )
    pool_size: int = Field(default=15, ge=1, le=100)
    max_overflow: int = Field(default=30, ge=0, le=100)
    pool_timeout: int = Field(default=30, ge=1)
    echo: bool = Field(default=False, description="Echo SQL queries")

    @property
    def is_sqlite(self) -> bool:
        """Check if using SQLite database."""
        return self.url.startswith("sqlite")

    @property
    def is_postgres(self) -> bool:
        """Check if using PostgreSQL database."""
        return "postgresql" in self.url


class RedisSettings(BaseSettings):
    """Redis connection settings."""

    model_config = SettingsConfigDict(env_prefix="MASS_REDIS_")

    url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )
    max_connections: int = Field(default=50, ge=1)
    socket_timeout: float = Field(default=5.0, ge=0.1)


class AuthSettings(BaseSettings):
    """Authentication settings."""

    model_config = SettingsConfigDict(env_prefix="MASS_AUTH_")

    secret_key: SecretStr = Field(
        default=SecretStr("change-me-in-production"),
        description="Secret key for JWT signing",
    )
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=60, ge=1)
    refresh_token_expire_days: int = Field(default=7, ge=1)
    api_key_prefix: str = Field(default="mass_")
    api_key_salt: str = Field(
        default="mass-api-key-salt-change-in-production",
        description="Salt for API key hashing",
    )


class StorageSettings(BaseSettings):
    """Blob storage settings."""

    model_config = SettingsConfigDict(env_prefix="MASS_STORAGE_")

    provider: Literal["local", "s3", "azure", "gcs"] = Field(default="local")
    local_path: str = Field(default="./data/storage")

    # S3
    s3_bucket: str = Field(default="")
    s3_region: str = Field(default="us-east-1")
    s3_access_key: SecretStr = Field(default=SecretStr(""))
    s3_secret_key: SecretStr = Field(default=SecretStr(""))

    # Azure
    azure_container: str = Field(default="")
    azure_connection_string: SecretStr = Field(default=SecretStr(""))

    # GCS
    gcs_bucket: str = Field(default="")
    gcs_credentials_file: str = Field(default="")


class QueueSettings(BaseSettings):
    """Message queue settings."""

    model_config = SettingsConfigDict(env_prefix="MASS_QUEUE_")

    provider: Literal["memory", "redis", "sqs", "servicebus", "pubsub"] = Field(
        default="redis"
    )

    # AWS SQS
    sqs_queue_url: str = Field(default="")
    sqs_region: str = Field(default="us-east-1")

    # Azure Service Bus
    servicebus_connection_string: SecretStr = Field(default=SecretStr(""))
    servicebus_queue_name: str = Field(default="mass-jobs")

    # GCP Pub/Sub
    pubsub_project_id: str = Field(default="")
    pubsub_topic_id: str = Field(default="mass-jobs")
    pubsub_subscription_id: str = Field(default="mass-jobs-sub")


class MassSettings(BaseSettings):
    """Main MASS application settings."""

    model_config = SettingsConfigDict(
        env_prefix="MASS_",
        env_nested_delimiter="__",
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="MASS")
    environment: Literal["development", "staging", "production"] = Field(
        default="development"
    )
    debug: bool = Field(default=False)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO"
    )

    # API
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_workers: int = Field(default=4, ge=1)
    api_cors_origins: list[str] = Field(default=["*"])
    api_rate_limit: int = Field(default=100, description="Requests per minute")

    # Scanning
    scan_timeout_seconds: int = Field(default=3600, ge=60)
    scan_max_concurrent: int = Field(default=10, ge=1)
    probe_batch_size: int = Field(default=50, ge=1, le=500)

    # Thread pool / concurrency tuning
    scan_thread_pool_size: int = Field(
        default=20, ge=1, le=200,
        description="Thread pool size for scan execution",
    )
    interrogation_thread_pool_size: int = Field(
        default=8, ge=1, le=100,
        description="Thread pool size for interrogation execution",
    )
    probe_max_concurrent: int = Field(
        default=5, ge=1, le=50,
        description="Max concurrent probes per scan",
    )
    probe_max_concurrent_prompts: int = Field(
        default=2, ge=1, le=20,
        description="Max concurrent prompts per probe",
    )

    # Platform-wide LLM defaults
    default_provider: str = Field(
        default="ollama",
        description="Default LLM provider (ollama/openai/anthropic/gemini/grok)",
    )
    default_model: str = Field(
        default="",
        description="Default model name. Blank = use provider default.",
    )

    # Per-activity LLM overrides (JSON string from env)
    activity_overrides: str = Field(
        default="{}",
        description=(
            "JSON string of per-activity model overrides. "
            "Keys: chat, code_analysis, verdict, threat_model, "
            "explainability, guardrails, finding_verification. "
            "Values: objects with optional 'provider' and 'model' fields."
        ),
    )

    @property
    def parsed_activity_overrides(self) -> dict[str, dict[str, str]]:
        """Parse the activity_overrides JSON string into a dict."""
        import json as _json

        try:
            data = _json.loads(self.activity_overrides)
            return data if isinstance(data, dict) else {}
        except (ValueError, TypeError):
            return {}

    # Configurable directory paths
    targets_dir: str = Field(default="/app/targets", description="Static analysis targets directory")
    downloads_dir: str = Field(default="/app/downloads", description="Downloads/uploads directory")
    github_clones_dir: str = Field(default="/app/github_clones", description="GitHub clones directory")
    strategies_dir: str = Field(default="/app/data/strategies", description="Interrogation strategies directory")
    reports_dir: str = Field(default="/app/data/reports", description="Report output directory")
    sandbox_scenarios_dir: str = Field(default="/app/data/sandbox/scenarios", description="Sandbox scenarios directory")
    guardrails_export_dir: str = Field(default="/app/data/guardrails_export", description="Guardrails export directory")

    # CI/CD Integration
    cicd_webhook_timeout: int = Field(
        default=30, ge=5, le=120,
        description="Max seconds to process a CI/CD webhook before timeout",
    )
    cicd_gate_default_threshold: str = Field(
        default="high",
        description="Default severity threshold for CI/CD gates: critical, high, medium, low",
    )
    supply_chain_scan_timeout: int = Field(
        default=300, ge=30, le=3600,
        description="Max seconds for a supply chain scan before timeout",
    )
    supply_chain_license_policy: str = Field(
        default="warn",
        description="License policy: warn (flag non-permissive), strict (fail on copyleft), permissive_only",
    )
    privacy_default_frameworks: str = Field(
        default="gdpr,owasp_llm",
        description="Comma-separated default privacy frameworks for assessments",
    )
    privacy_pii_scan_enabled: bool = Field(
        default=True,
        description="Enable PII scanning in privacy assessments",
    )

    # Model provider API keys
    openai_api_key: SecretStr = Field(default=SecretStr(""))
    anthropic_api_key: SecretStr = Field(default=SecretStr(""))
    google_api_key: SecretStr = Field(default=SecretStr(""))
    grok_api_key: SecretStr = Field(default=SecretStr(""))

    # Nested settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    queue: QueueSettings = Field(default_factory=QueueSettings)

    @field_validator("environment", mode="before")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Normalize environment name."""
        return v.lower()

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.environment == "development"


def _load_platform_settings_from_json() -> None:
    """Load saved platform settings into os.environ before MassSettings init.

    Reads ``data/platform_settings.json`` (persisted via the Settings UI)
    and injects saved values into ``os.environ`` so that pydantic-settings
    picks them up.  Called once, right before the first ``MassSettings()``
    instantiation.
    """
    import json as _json

    for candidate in [Path("/app/data/platform_settings.json"), Path("data/platform_settings.json")]:
        if candidate.is_file():
            try:
                data = _json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for key, value in data.items():
                        if value:
                            os.environ[key] = value
            except Exception:
                pass
            break


# Ensure persisted settings are in os.environ BEFORE the first
# MassSettings() is constructed (which reads from os.environ).
_load_platform_settings_from_json()


@lru_cache
def get_settings() -> MassSettings:
    """Get cached settings instance.

    Returns:
        MassSettings: Application settings loaded from environment.
    """
    return MassSettings()
