"""Redis cache abstraction.

Provides a clean interface for caching with TTL support and JSON serialization.
"""

import json
from typing import Any, TypeVar

from redis.asyncio import Redis

from mass.core.config import get_settings

T = TypeVar("T")

# Global Redis client
_redis: Redis | None = None


async def get_redis() -> Redis:
    """Get or create Redis client.

    Returns:
        Redis: Async Redis client.
    """
    global _redis
    if _redis is None:
        settings = get_settings()
        _redis = Redis.from_url(
            settings.redis.url,
            max_connections=settings.redis.max_connections,
            socket_timeout=settings.redis.socket_timeout,
            decode_responses=True,
        )
    return _redis


async def close_redis() -> None:
    """Close Redis connection."""
    global _redis
    if _redis is not None:
        await _redis.close()
        _redis = None


async def check_redis_health() -> dict[str, Any]:
    """Check Redis connectivity.

    Returns:
        Health check result.
    """
    try:
        redis = await get_redis()
        await redis.ping()
        return {"status": "healthy", "redis": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "redis": "disconnected", "error": str(e)}


class Cache:
    """Redis cache with JSON serialization.

    Provides typed get/set operations with automatic JSON encoding/decoding.

    Example:
        ```python
        cache = Cache(prefix="mass")

        # Store value with 5 minute TTL
        await cache.set("user:123", {"name": "Test"}, ttl=300)

        # Retrieve value
        user = await cache.get("user:123")

        # Delete value
        await cache.delete("user:123")
        ```
    """

    def __init__(
        self,
        prefix: str = "mass",
        default_ttl: int = 3600,
    ) -> None:
        """Initialize cache.

        Args:
            prefix: Key prefix for namespacing.
            default_ttl: Default TTL in seconds.
        """
        self.prefix = prefix
        self.default_ttl = default_ttl

    def _make_key(self, key: str) -> str:
        """Create prefixed cache key.

        Args:
            key: Base key.

        Returns:
            Prefixed key.
        """
        return f"{self.prefix}:{key}"

    async def get(self, key: str) -> Any | None:
        """Get value from cache.

        Args:
            key: Cache key.

        Returns:
            Cached value or None.
        """
        redis = await get_redis()
        value = await redis.get(self._make_key(key))
        if value is None:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    async def get_typed(self, key: str, type_: type[T]) -> T | None:
        """Get typed value from cache.

        Args:
            key: Cache key.
            type_: Expected type (for documentation).

        Returns:
            Cached value or None.
        """
        return await self.get(key)

    async def set(
        self,
        key: str,
        value: Any,
        ttl: int | None = None,
    ) -> bool:
        """Set value in cache.

        Args:
            key: Cache key.
            value: Value to cache (will be JSON encoded).
            ttl: Time to live in seconds.

        Returns:
            True if successful.
        """
        redis = await get_redis()
        ttl = ttl or self.default_ttl
        json_value = json.dumps(value)
        await redis.setex(self._make_key(key), ttl, json_value)
        return True

    async def delete(self, key: str) -> bool:
        """Delete value from cache.

        Args:
            key: Cache key.

        Returns:
            True if key existed and was deleted.
        """
        redis = await get_redis()
        result = await redis.delete(self._make_key(key))
        return result > 0

    async def exists(self, key: str) -> bool:
        """Check if key exists.

        Args:
            key: Cache key.

        Returns:
            True if key exists.
        """
        redis = await get_redis()
        return await redis.exists(self._make_key(key)) > 0

    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration on existing key.

        Args:
            key: Cache key.
            ttl: Time to live in seconds.

        Returns:
            True if key exists and expiration was set.
        """
        redis = await get_redis()
        return await redis.expire(self._make_key(key), ttl)

    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment integer value.

        Args:
            key: Cache key.
            amount: Amount to increment.

        Returns:
            New value.
        """
        redis = await get_redis()
        return await redis.incrby(self._make_key(key), amount)

    async def decr(self, key: str, amount: int = 1) -> int:
        """Decrement integer value.

        Args:
            key: Cache key.
            amount: Amount to decrement.

        Returns:
            New value.
        """
        redis = await get_redis()
        return await redis.decrby(self._make_key(key), amount)

    async def clear_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern.

        Args:
            pattern: Glob pattern (e.g., "user:*").

        Returns:
            Number of deleted keys.
        """
        redis = await get_redis()
        full_pattern = self._make_key(pattern)
        keys = []
        async for key in redis.scan_iter(match=full_pattern):
            keys.append(key)
        if keys:
            return await redis.delete(*keys)
        return 0

    async def mget(self, *keys: str) -> dict[str, Any]:
        """Get multiple values.

        Args:
            *keys: Cache keys.

        Returns:
            Dictionary of key -> value.
        """
        redis = await get_redis()
        full_keys = [self._make_key(k) for k in keys]
        values = await redis.mget(full_keys)
        result = {}
        for key, value in zip(keys, values):
            if value is not None:
                try:
                    result[key] = json.loads(value)
                except json.JSONDecodeError:
                    result[key] = value
        return result

    async def mset(
        self,
        mapping: dict[str, Any],
        ttl: int | None = None,
    ) -> bool:
        """Set multiple values.

        Args:
            mapping: Dictionary of key -> value.
            ttl: Time to live in seconds.

        Returns:
            True if successful.
        """
        redis = await get_redis()
        ttl = ttl or self.default_ttl

        # Use pipeline for efficiency
        pipe = redis.pipeline()
        for key, value in mapping.items():
            full_key = self._make_key(key)
            json_value = json.dumps(value)
            pipe.setex(full_key, ttl, json_value)
        await pipe.execute()
        return True


# Default cache instance
cache = Cache()
