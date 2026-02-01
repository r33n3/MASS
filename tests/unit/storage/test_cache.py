"""Tests for cache module."""

import pytest

from mass.storage.cache import Cache


class TestCache:
    """Tests for Cache class."""

    def test_cache_initialization(self) -> None:
        """Test Cache initialization."""
        cache = Cache(prefix="test", default_ttl=300)
        assert cache.prefix == "test"
        assert cache.default_ttl == 300

    def test_cache_default_values(self) -> None:
        """Test Cache default values."""
        cache = Cache()
        assert cache.prefix == "mass"
        assert cache.default_ttl == 3600

    def test_make_key(self) -> None:
        """Test key prefixing."""
        cache = Cache(prefix="test")
        assert cache._make_key("user:123") == "test:user:123"
        assert cache._make_key("scan") == "test:scan"

    def test_make_key_custom_prefix(self) -> None:
        """Test key with custom prefix."""
        cache = Cache(prefix="myapp")
        assert cache._make_key("data") == "myapp:data"
