"""Tests for mass.core.config module."""

import os
from unittest.mock import patch

import pytest

from mass.core.config import (
    AuthSettings,
    DatabaseSettings,
    MassSettings,
    QueueSettings,
    RedisSettings,
    StorageSettings,
    get_settings,
)


class TestDatabaseSettings:
    """Tests for DatabaseSettings."""

    def test_default_values(self) -> None:
        """Test default database settings."""
        settings = DatabaseSettings()
        assert "postgresql" in settings.url
        assert settings.pool_size == 10
        assert settings.max_overflow == 20
        assert settings.echo is False

    def test_pool_size_validation(self) -> None:
        """Test pool size validation."""
        settings = DatabaseSettings(pool_size=50)
        assert settings.pool_size == 50


class TestRedisSettings:
    """Tests for RedisSettings."""

    def test_default_values(self) -> None:
        """Test default Redis settings."""
        settings = RedisSettings()
        assert "redis://localhost" in settings.url
        assert settings.max_connections == 50


class TestAuthSettings:
    """Tests for AuthSettings."""

    def test_default_values(self) -> None:
        """Test default auth settings."""
        settings = AuthSettings()
        assert settings.algorithm == "HS256"
        assert settings.access_token_expire_minutes == 60
        assert settings.api_key_prefix == "mass_"

    def test_secret_key_is_secret(self) -> None:
        """Test that secret key is masked."""
        settings = AuthSettings()
        # SecretStr should not expose value in str()
        assert "change-me" not in str(settings.secret_key)


class TestStorageSettings:
    """Tests for StorageSettings."""

    def test_default_provider_is_local(self) -> None:
        """Test default storage provider."""
        settings = StorageSettings()
        assert settings.provider == "local"

    def test_valid_providers(self) -> None:
        """Test valid storage providers."""
        for provider in ["local", "s3", "azure", "gcs"]:
            settings = StorageSettings(provider=provider)
            assert settings.provider == provider


class TestQueueSettings:
    """Tests for QueueSettings."""

    def test_default_provider_is_redis(self) -> None:
        """Test default queue provider."""
        settings = QueueSettings()
        assert settings.provider == "redis"

    def test_valid_providers(self) -> None:
        """Test valid queue providers."""
        for provider in ["memory", "redis", "sqs", "servicebus", "pubsub"]:
            settings = QueueSettings(provider=provider)
            assert settings.provider == provider


class TestMassSettings:
    """Tests for MassSettings."""

    def test_default_values(self) -> None:
        """Test default MASS settings."""
        settings = MassSettings()
        assert settings.app_name == "MASS"
        assert settings.environment == "development"
        assert settings.debug is False
        assert settings.api_port == 8000

    def test_is_production_property(self) -> None:
        """Test is_production property."""
        dev_settings = MassSettings(environment="development")
        assert dev_settings.is_production is False
        assert dev_settings.is_development is True

        prod_settings = MassSettings(environment="production")
        assert prod_settings.is_production is True
        assert prod_settings.is_development is False

    def test_environment_normalization(self) -> None:
        """Test that environment is normalized to lowercase."""
        settings = MassSettings(environment="PRODUCTION")
        assert settings.environment == "production"

    def test_nested_settings(self) -> None:
        """Test that nested settings are initialized."""
        settings = MassSettings()
        assert isinstance(settings.database, DatabaseSettings)
        assert isinstance(settings.redis, RedisSettings)
        assert isinstance(settings.auth, AuthSettings)
        assert isinstance(settings.storage, StorageSettings)
        assert isinstance(settings.queue, QueueSettings)

    def test_api_rate_limit_default(self) -> None:
        """Test default API rate limit."""
        settings = MassSettings()
        assert settings.api_rate_limit == 100


class TestGetSettings:
    """Tests for get_settings function."""

    def test_returns_settings_instance(self) -> None:
        """Test that get_settings returns MassSettings."""
        # Clear cache to ensure fresh instance
        get_settings.cache_clear()
        settings = get_settings()
        assert isinstance(settings, MassSettings)

    def test_settings_are_cached(self) -> None:
        """Test that settings are cached."""
        get_settings.cache_clear()
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2
