"""Configuration management for MASS.

Uses Pydantic Settings for environment-based configuration with
sensible defaults for development and production.
"""

from functools import lru_cache
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

    # Model providers (API keys)
    openai_api_key: SecretStr = Field(default=SecretStr(""))
    anthropic_api_key: SecretStr = Field(default=SecretStr(""))
    google_api_key: SecretStr = Field(default=SecretStr(""))

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


@lru_cache
def get_settings() -> MassSettings:
    """Get cached settings instance.

    Returns:
        MassSettings: Application settings loaded from environment.
    """
    return MassSettings()
