"""Shared connection pools for LLM providers.

Provides singleton httpx clients keyed by (provider, base_url) so that
TCP/TLS connections are reused across all runner instances.  At 100
concurrent scans making 15+ LLM calls each, this avoids 1 500+ fresh
connection set-ups.

For SDK-based providers (OpenAI, Anthropic, etc.) the vendor SDKs
manage their own internal httpx pools.  The runners themselves should
cache their async SDK client (``self._async_client``) so the internal
pool is reused across calls — see each runner's ``_get_async_client``
method.
"""

import asyncio
import logging
import time
import threading

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared httpx pools (used by Ollama and any raw-httpx runner)
# ---------------------------------------------------------------------------

_sync_pools: dict[str, httpx.Client] = {}
_async_pools: dict[str, httpx.AsyncClient] = {}


def get_httpx_pool(
    provider: str,
    base_url: str = "",
    timeout: float = 60.0,
) -> httpx.Client:
    """Return a shared *synchronous* httpx client for *provider*."""
    key = f"{provider}:{base_url}"
    if key not in _sync_pools:
        _sync_pools[key] = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=10.0),
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=20,
            ),
        )
        logger.debug("Created sync httpx pool for %s", key)
    return _sync_pools[key]


def get_httpx_async_pool(
    provider: str,
    base_url: str = "",
    timeout: float = 60.0,
) -> httpx.AsyncClient:
    """Return a shared *asynchronous* httpx client for *provider*."""
    key = f"{provider}:{base_url}"
    if key not in _async_pools:
        _async_pools[key] = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=10.0),
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=20,
            ),
        )
        logger.debug("Created async httpx pool for %s", key)
    return _async_pools[key]


async def close_all_pools() -> None:
    """Close every pool.  Call once on application shutdown."""
    for pool in _sync_pools.values():
        pool.close()
    _sync_pools.clear()

    for pool in _async_pools.values():
        await pool.aclose()
    _async_pools.clear()
    logger.info("All LLM connection pools closed")


# ---------------------------------------------------------------------------
# Per-provider rate limiter (token bucket)
# ---------------------------------------------------------------------------

class ProviderRateLimiter:
    """Async token-bucket rate limiter keyed by LLM provider.

    Limits are expressed as *requests per minute*.  A value of ``0``
    means unlimited (no throttling).  Defaults are intentionally
    conservative so a fresh deployment doesn't burn through quotas.
    """

    # Requests-per-minute defaults.  Override via MASS_LLM_RPM_<PROVIDER>.
    DEFAULTS: dict[str, int] = {
        "openai": 500,
        "anthropic": 200,
        "gemini": 300,
        "grok": 200,
        "bedrock": 200,
        "azure_openai": 500,
        "ollama": 0,  # unlimited (local)
    }

    def __init__(self) -> None:
        self._buckets: dict[str, float] = {}
        self._last_refill: dict[str, float] = {}
        self._limits: dict[str, float] = {}
        self._async_lock = asyncio.Lock()
        self._sync_lock = threading.Lock()

    def _get_rpm(self, provider: str) -> int:
        """Return the RPM limit for *provider*, checking env overrides."""
        import os
        env_key = f"MASS_LLM_RPM_{provider.upper()}"
        env_val = os.environ.get(env_key)
        if env_val is not None:
            return int(env_val)
        return self.DEFAULTS.get(provider, 200)

    def _refill(self, provider: str) -> None:
        """Refill bucket based on elapsed time."""
        rpm = self._get_rpm(provider)
        if rpm <= 0:
            return  # unlimited
        now = time.monotonic()
        if provider not in self._last_refill:
            self._buckets[provider] = float(rpm)
            self._last_refill[provider] = now
            return
        elapsed = now - self._last_refill[provider]
        self._last_refill[provider] = now
        tokens_per_sec = rpm / 60.0
        self._buckets[provider] = min(
            float(rpm),
            self._buckets.get(provider, 0.0) + elapsed * tokens_per_sec,
        )

    async def acquire(self, provider: str) -> None:
        """Wait until a token is available for *provider* (async)."""
        rpm = self._get_rpm(provider)
        if rpm <= 0:
            return  # unlimited

        while True:
            async with self._async_lock:
                self._refill(provider)
                if self._buckets.get(provider, 0.0) >= 1.0:
                    self._buckets[provider] -= 1.0
                    return
            # Back off briefly before retrying
            await asyncio.sleep(0.1)

    def acquire_sync(self, provider: str) -> None:
        """Block until a token is available for *provider* (sync)."""
        rpm = self._get_rpm(provider)
        if rpm <= 0:
            return  # unlimited

        while True:
            with self._sync_lock:
                self._refill(provider)
                if self._buckets.get(provider, 0.0) >= 1.0:
                    self._buckets[provider] -= 1.0
                    return
            time.sleep(0.1)


# Singleton instance
rate_limiter = ProviderRateLimiter()
