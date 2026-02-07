"""Ollama container manager.

Talks to the Ollama REST API to check health, list models, and pull
models on demand. Used by the interrogation flow to auto-setup models
before running adversarial conversations.
"""

import logging
import os

import httpx

logger = logging.getLogger(__name__)

# Timeout for health checks and model listing
_QUICK_TIMEOUT = 10.0
# Timeout for model pulls (large models can take 10+ minutes)
_PULL_TIMEOUT = 1800.0


def get_ollama_hosts() -> dict[str, str]:
    """Return configured Ollama host URLs keyed by role."""
    return {
        "destination": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        "source": os.getenv("OLLAMA_ATTACKER_HOST", "http://localhost:11435"),
    }


async def check_health(host_url: str) -> bool:
    """Check if an Ollama instance is reachable.

    Args:
        host_url: Ollama server URL (e.g. http://ollama:11434).

    Returns:
        True if Ollama is responsive.
    """
    try:
        async with httpx.AsyncClient(timeout=_QUICK_TIMEOUT) as client:
            resp = await client.get(f"{host_url.rstrip('/')}/api/tags")
            resp.raise_for_status()
            return True
    except Exception as e:
        logger.debug("Ollama health check failed for %s: %s", host_url, e)
        return False


async def list_models(host_url: str) -> list[dict]:
    """List models available on an Ollama instance.

    Returns:
        List of model dicts with name, size, modified_at, etc.
    """
    try:
        async with httpx.AsyncClient(timeout=_QUICK_TIMEOUT) as client:
            resp = await client.get(f"{host_url.rstrip('/')}/api/tags")
            resp.raise_for_status()
            return resp.json().get("models", [])
    except Exception as e:
        logger.warning("Failed to list models from %s: %s", host_url, e)
        return []


async def is_model_available(host_url: str, model_name: str) -> bool:
    """Check if a specific model is pulled on an Ollama instance.

    Handles both exact matches (qwen3:8b) and base name matches (qwen3).
    """
    models = await list_models(host_url)
    # Normalize: Ollama returns names like "qwen3:8b", user might pass "qwen3:8b" or "qwen3"
    for m in models:
        name = m.get("name", "")
        if name == model_name or name.startswith(f"{model_name}:"):
            return True
        # Also check without tag: "qwen3:8b" matches query "qwen3:8b"
        if model_name == name.split(":")[0]:
            return True
    return False


async def pull_model(host_url: str, model_name: str) -> tuple[bool, str]:
    """Pull a model on an Ollama instance.

    This is a blocking call that waits for the pull to complete.
    Can take several minutes for large models.

    Args:
        host_url: Ollama server URL.
        model_name: Model to pull (e.g. "qwen3:8b").

    Returns:
        Tuple of (success: bool, message: str).
    """
    url = f"{host_url.rstrip('/')}/api/pull"
    payload = {"name": model_name, "stream": False}

    logger.info("Pulling model %s on %s (this may take a while)...", model_name, host_url)

    try:
        async with httpx.AsyncClient(timeout=_PULL_TIMEOUT) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status", "unknown")
            logger.info("Model pull complete: %s — %s", model_name, status)
            return True, f"Model {model_name} ready ({status})"
    except httpx.TimeoutException:
        msg = f"Model pull timed out for {model_name} on {host_url} (>{_PULL_TIMEOUT}s)"
        logger.error(msg)
        return False, msg
    except httpx.ConnectError:
        msg = f"Cannot reach Ollama at {host_url}"
        logger.error(msg)
        return False, msg
    except Exception as e:
        msg = f"Failed to pull {model_name} on {host_url}: {e}"
        logger.error(msg)
        return False, msg


async def ensure_model_ready(host_url: str, model_name: str) -> tuple[bool, str]:
    """Ensure a model is available on an Ollama instance.

    Checks health, checks if model exists, pulls if needed.

    Args:
        host_url: Ollama server URL.
        model_name: Model to ensure is ready.

    Returns:
        Tuple of (success: bool, message: str).
    """
    # 1. Health check
    healthy = await check_health(host_url)
    if not healthy:
        return False, f"Ollama not reachable at {host_url}"

    # 2. Check if model is already available
    available = await is_model_available(host_url, model_name)
    if available:
        logger.info("Model %s already available on %s", model_name, host_url)
        return True, f"Model {model_name} ready"

    # 3. Pull the model
    logger.info("Model %s not found on %s, pulling...", model_name, host_url)
    return await pull_model(host_url, model_name)
