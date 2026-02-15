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

import logging

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
