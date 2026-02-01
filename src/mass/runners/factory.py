"""Runner factory.

Factory for creating runner instances based on provider/model specification.
"""

from typing import Any

from mass.runners.base import BaseRunner, runner_registry


def create_runner(
    provider: str,
    model: str | None = None,
    **kwargs: Any,
) -> BaseRunner | None:
    """Create a runner instance for a provider.

    Args:
        provider: Provider name (openai, anthropic, ollama, etc.).
        model: Optional model identifier.
        **kwargs: Provider-specific configuration.

    Returns:
        Runner instance or None if provider not found.
    """
    # Map provider names to runner names
    provider_map = {
        "openai": "openai",
        "anthropic": "anthropic",
        "claude": "anthropic",
        "ollama": "ollama",
        "local": "ollama",
    }

    runner_name = provider_map.get(provider.lower())
    if not runner_name:
        # Try direct lookup
        runner_name = provider

    return runner_registry.get(runner_name, model=model, **kwargs)


def create_runner_from_url(url: str, **kwargs: Any) -> BaseRunner | None:
    """Create a runner from an API URL.

    Args:
        url: API endpoint URL.
        **kwargs: Additional configuration.

    Returns:
        Runner instance or None if unable to determine provider.
    """
    url_lower = url.lower()

    if "openai" in url_lower or "api.openai.com" in url_lower:
        return create_runner("openai", base_url=url, **kwargs)
    elif "anthropic" in url_lower or "api.anthropic.com" in url_lower:
        return create_runner("anthropic", base_url=url, **kwargs)
    elif "localhost" in url_lower or "127.0.0.1" in url_lower:
        # Assume Ollama for local URLs
        return create_runner("ollama", base_url=url, **kwargs)

    return None
