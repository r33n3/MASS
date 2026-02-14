"""Unified LLM configuration resolution for the MASS platform.

All features (chat, sandbox, code analysis, verification, etc.) resolve
provider / model / API-key / endpoint through this module so that the
"Platform Defaults" set in MassSettings flow everywhere automatically.

Resolution order (first non-empty wins):
    1. Explicit parameter (from request body / localStorage)
    2. Platform default  (MASS_DEFAULT_PROVIDER / MASS_DEFAULT_MODEL in .env)
    3. Feature-specific model override (e.g. hermes3:8b for code analysis)
    4. PROVIDER_DEFAULTS  (hardcoded per-provider fallback)

API-key resolution:
    1. Explicit parameter
    2. MassSettings       (MASS_OPENAI_API_KEY etc. from .env)
    3. Direct env var     (OPENAI_API_KEY — backward compat)
"""

from __future__ import annotations

import os
from typing import NamedTuple

# ── Consolidated provider defaults ────────────────────────────────────
# Single source of truth — replaces duplicates in chat.py & llm_analyzer.py.

PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "ollama": {
        "model": "qwen3:8b",
        "endpoint_env": "OLLAMA_HOST",
        "endpoint_fallback": "http://ollama:11434",
    },
    "openai": {
        "model": "gpt-4o",
        "endpoint_env": "OPENAI_API_BASE",
        "endpoint_fallback": "https://api.openai.com/v1",
        "key_env": "OPENAI_API_KEY",
        "settings_attr": "openai_api_key",
    },
    "anthropic": {
        "model": "claude-sonnet-4-5-20250929",
        "endpoint_env": "ANTHROPIC_API_BASE",
        "endpoint_fallback": "https://api.anthropic.com",
        "key_env": "ANTHROPIC_API_KEY",
        "settings_attr": "anthropic_api_key",
    },
    "gemini": {
        "model": "gemini-2.0-flash",
        "endpoint_env": "GEMINI_API_BASE",
        "endpoint_fallback": "https://generativelanguage.googleapis.com/v1beta",
        "key_env": "GEMINI_API_KEY",
        "settings_attr": "google_api_key",
    },
    "grok": {
        "model": "grok-3",
        "endpoint_env": "GROK_API_BASE",
        "endpoint_fallback": "https://api.x.ai/v1",
        "key_env": "XAI_API_KEY",
        "settings_attr": "grok_api_key",
    },
}


class LLMConfig(NamedTuple):
    provider: str
    model: str
    api_key: str
    endpoint: str


def resolve_llm_config(
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    endpoint: str | None = None,
    *,
    feature_model_override: str | None = None,
) -> LLMConfig:
    """Resolve LLM configuration with unified fallback chain.

    Parameters
    ----------
    provider : explicit provider from request/UI (highest priority)
    model    : explicit model from request/UI
    api_key  : explicit API key from request/UI
    endpoint : explicit endpoint from request/UI
    feature_model_override : per-feature default model (e.g. "hermes3:8b"
        for code analysis).  Only used when platform default is also blank.

    Returns
    -------
    LLMConfig(provider, model, api_key, endpoint)
    """
    from mass.core.config import get_settings

    settings = get_settings()

    # ── Provider ──────────────────────────────────────────────────
    resolved_provider = provider or settings.default_provider or "ollama"

    defaults = PROVIDER_DEFAULTS.get(resolved_provider, PROVIDER_DEFAULTS["ollama"])

    # ── Model ─────────────────────────────────────────────────────
    resolved_model = (
        model
        or settings.default_model
        or feature_model_override
        or defaults.get("model", "")
    )

    # ── Endpoint ──────────────────────────────────────────────────
    resolved_endpoint = (
        endpoint
        or os.getenv(defaults.get("endpoint_env", ""), "")
        or defaults.get("endpoint_fallback", "")
    )

    # ── API key ───────────────────────────────────────────────────
    resolved_key = api_key or resolve_api_key(resolved_provider)

    return LLMConfig(resolved_provider, resolved_model, resolved_key, resolved_endpoint)


def resolve_api_key(provider: str) -> str:
    """Resolve API key for *provider* from MassSettings then env vars.

    Checks MASS_*_API_KEY (via pydantic-settings) first, then the raw
    env var (OPENAI_API_KEY etc.) for backward compatibility.
    """
    defaults = PROVIDER_DEFAULTS.get(provider, {})
    settings_attr = defaults.get("settings_attr")

    # 1. MassSettings (MASS_OPENAI_API_KEY etc.)
    if settings_attr:
        try:
            from mass.core.config import get_settings

            secret = getattr(get_settings(), settings_attr, None)
            if secret:
                val = secret.get_secret_value()
                if val:
                    return val
        except Exception:
            pass

    # 2. Direct env var (backward compat)
    key_env = defaults.get("key_env", "")
    if key_env:
        val = os.getenv(key_env, "")
        if val:
            return val

    return ""
