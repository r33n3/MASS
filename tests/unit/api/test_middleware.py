"""Tests for API middleware."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from mass.api.middleware.auth import hash_api_key, generate_api_key, get_key_prefix
from mass.api.middleware.tenant import TenantContext
from mass.api.middleware.rate_limit import TokenBucket


class TestAuthMiddleware:
    """Tests for authentication helpers."""

    def test_generate_api_key(self) -> None:
        """Test API key generation."""
        key1, hash1 = generate_api_key()
        key2, hash2 = generate_api_key()

        # Keys should be unique
        assert key1 != key2
        assert hash1 != hash2

        # Key should have expected format
        assert key1.startswith("mass_")
        assert len(key1) > 20

    def test_hash_api_key(self) -> None:
        """Test API key hashing."""
        key = "mass_test123456789"
        hash1 = hash_api_key(key)
        hash2 = hash_api_key(key)

        # Same key should produce same hash
        assert hash1 == hash2

        # Different keys should produce different hashes
        hash3 = hash_api_key("mass_different")
        assert hash1 != hash3

    def test_get_key_prefix(self) -> None:
        """Test key prefix extraction."""
        key = "mass_abcdefghijklmnop"
        prefix = get_key_prefix(key)

        # Prefix should be first part of key
        assert prefix == "mass_abcdefgh"
        assert len(prefix) == 13


class TestTenantContext:
    """Tests for tenant context."""

    def test_context_manager(self) -> None:
        """Test tenant context manager."""
        assert TenantContext.get_current_tenant_id() is None

        with TenantContext("tenant-123"):
            assert TenantContext.get_current_tenant_id() == "tenant-123"

        assert TenantContext.get_current_tenant_id() is None

    def test_nested_context(self) -> None:
        """Test nested tenant contexts."""
        with TenantContext("tenant-1"):
            assert TenantContext.get_current_tenant_id() == "tenant-1"

            with TenantContext("tenant-2"):
                assert TenantContext.get_current_tenant_id() == "tenant-2"

            assert TenantContext.get_current_tenant_id() == "tenant-1"

    def test_require_tenant(self) -> None:
        """Test require_tenant raises when no context."""
        with pytest.raises(RuntimeError):
            TenantContext.require_tenant()

        with TenantContext("tenant-123"):
            assert TenantContext.require_tenant() == "tenant-123"


class TestTokenBucket:
    """Tests for rate limiting token bucket."""

    @pytest.mark.asyncio
    async def test_token_bucket_consume(self) -> None:
        """Test token consumption."""
        bucket = TokenBucket(tokens_per_second=10, bucket_size=10)

        # Should be able to consume tokens
        assert await bucket.consume(5) is True
        assert await bucket.consume(5) is True

        # Bucket should be empty now
        assert await bucket.consume(1) is False

    @pytest.mark.asyncio
    async def test_token_bucket_refill(self) -> None:
        """Test token refill over time."""
        bucket = TokenBucket(tokens_per_second=1000, bucket_size=10)

        # Consume all tokens
        await bucket.consume(10)
        assert await bucket.consume(1) is False

        # Tokens should refill (due to high rate)
        import asyncio
        await asyncio.sleep(0.02)  # Wait for refill
        assert await bucket.consume(1) is True

    def test_retry_after(self) -> None:
        """Test retry-after calculation."""
        bucket = TokenBucket(tokens_per_second=1, bucket_size=10)
        bucket.tokens = 0.5

        retry = bucket.retry_after
        assert retry > 0
        assert retry < 1
