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
    # Ensure all runners are registered
    import mass.runners.api.openai  # noqa: F401
    import mass.runners.api.anthropic  # noqa: F401
    import mass.runners.api.ollama  # noqa: F401
    import mass.runners.api.bedrock  # noqa: F401
    import mass.runners.api.azure_openai  # noqa: F401
    import mass.runners.api.gemini  # noqa: F401
    import mass.runners.api.grok  # noqa: F401
    import mass.runners.api.browser  # noqa: F401

    # Map provider names to runner names
    provider_map = {
        "openai": "openai",
        "anthropic": "anthropic",
        "claude": "anthropic",
        "ollama": "ollama",
        "local": "ollama",
        "bedrock": "bedrock",
        "aws_bedrock": "bedrock",
        "aws": "bedrock",
        "azure_openai": "azure_openai",
        "azure": "azure_openai",
        "gemini": "gemini",
        "google": "gemini",
        "vertex": "gemini",
        "grok": "grok",
        "xai": "grok",
        "browser": "browser",
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

    if "openai.azure.com" in url_lower or "cognitiveservices.azure.com" in url_lower:
        return create_runner("azure_openai", azure_endpoint=url, **kwargs)
    elif "openai" in url_lower or "api.openai.com" in url_lower:
        return create_runner("openai", base_url=url, **kwargs)
    elif "anthropic" in url_lower or "api.anthropic.com" in url_lower:
        return create_runner("anthropic", base_url=url, **kwargs)
    elif "bedrock" in url_lower or "amazonaws.com" in url_lower:
        return create_runner("bedrock", **kwargs)
    elif "generativelanguage.googleapis.com" in url_lower or "aiplatform.googleapis.com" in url_lower:
        return create_runner("gemini", **kwargs)
    elif "api.x.ai" in url_lower:
        return create_runner("grok", base_url=url, **kwargs)
    elif "localhost" in url_lower or "127.0.0.1" in url_lower:
        # Assume Ollama for local URLs
        return create_runner("ollama", base_url=url, **kwargs)

    return None
