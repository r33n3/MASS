"""Unified LLM configuration resolution for the MASS platform.

All features (chat, sandbox, code analysis, verification, etc.) resolve
provider / model / API-key / endpoint through this module so that the
"Platform Defaults" set in MassSettings flow everywhere automatically.

Resolution order (first non-empty wins):
    1. Explicit parameter (from request body / localStorage)
    2. Activity override  (per-activity config from MASS_ACTIVITY_OVERRIDES)
    3. Platform default   (MASS_DEFAULT_PROVIDER / MASS_DEFAULT_MODEL in .env)
    4. Feature-specific model override (e.g. hermes3:8b for code analysis)
    5. PROVIDER_DEFAULTS  (hardcoded per-provider fallback)

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
        "model": "claude-sonnet-4-6",
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

# ── Valid activity identifiers for per-activity model overrides ───────
ACTIVITY_IDS = frozenset({
    "chat",
    "code_analysis",
    "verdict",
    "threat_model",
    "explainability",
    "guardrails",
    "finding_verification",
})


# ── Model-aware parameter adjustment ──────────────────────────────────
# Different models have different valid parameter ranges and names.
# This function adjusts request parameters to match model requirements.

# Prefixes that identify OpenAI reasoning models (restricted params)
_OPENAI_REASONING_PREFIXES = ("o1", "o3", "o4", "gpt-5", "gpt5")

# Default max_tokens per provider (conservative — models may accept more)
_DEFAULT_MAX_TOKENS: dict[str, int] = {
    "ollama": 4096,
    "openai": 4096,
    "anthropic": 8192,  # Anthropic models support much larger outputs
    "gemini": 8192,
    "grok": 4096,
}

# Reasoning models need a much larger budget because they consume tokens
# for internal reasoning BEFORE producing visible output.  e.g. GPT-5-mini
# used 4096 reasoning tokens and had 0 left for content at the 4096 cap.
_REASONING_MAX_TOKENS: int = 16384

# Max temperature per provider
_MAX_TEMPERATURE: dict[str, float] = {
    "ollama": 2.0,
    "openai": 2.0,
    "anthropic": 1.0,
    "gemini": 2.0,
    "grok": 2.0,
}


def is_reasoning_model(model: str) -> bool:
    """Check if a model is an OpenAI reasoning model with restricted params."""
    model_lower = model.lower()
    return any(model_lower.startswith(p) for p in _OPENAI_REASONING_PREFIXES)


def adjust_params_for_model(
    provider: str,
    model: str,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> dict[str, object]:
    """Return model-aware parameters for an LLM API call.

    Handles:
    - OpenAI reasoning models (o-series, GPT-5): omit temperature, use
      max_completion_tokens instead of max_tokens
    - Anthropic temperature clamping to [0.0, 1.0]
    - Provider-specific max_tokens defaults

    Returns dict with keys: temperature (or omitted), max_tokens_key, max_tokens_value
    """
    resolved_max = max_tokens or _DEFAULT_MAX_TOKENS.get(provider, 4096)
    max_temp = _MAX_TEMPERATURE.get(provider, 2.0)

    result: dict[str, object] = {}

    if provider in ("openai", "grok") and is_reasoning_model(model):
        # Reasoning models: no temperature, max_completion_tokens not max_tokens.
        # They need a large budget because reasoning tokens are consumed BEFORE
        # visible output tokens — at 4096 the model often exhausts the budget
        # on reasoning alone and returns empty content.
        reasoning_max = max_tokens or _REASONING_MAX_TOKENS
        result["skip_temperature"] = True
        result["max_tokens_key"] = "max_completion_tokens"
        result["max_tokens_value"] = reasoning_max
        result["is_reasoning"] = True
    else:
        # Standard models
        if temperature is not None:
            result["temperature"] = min(max(0.0, temperature), max_temp)
        result["max_tokens_key"] = "max_tokens"
        result["max_tokens_value"] = resolved_max
        result["skip_temperature"] = False
        result["is_reasoning"] = False

    return result


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
    activity: str | None = None,
    feature_model_override: str | None = None,
) -> LLMConfig:
    """Resolve LLM configuration with unified fallback chain.

    Parameters
    ----------
    provider : explicit provider from request/UI (highest priority)
    model    : explicit model from request/UI
    api_key  : explicit API key from request/UI
    endpoint : explicit endpoint from request/UI
    activity : activity identifier (e.g. "chat", "verdict") for
        per-activity model overrides configured in platform settings.
    feature_model_override : per-feature default model (e.g. "hermes3:8b"
        for code analysis).  Only used when platform default is also blank.

    Returns
    -------
    LLMConfig(provider, model, api_key, endpoint)
    """
    from mass.core.config import get_settings

    settings = get_settings()

    # ── Activity override lookup ──────────────────────────────────
    activity_provider = None
    activity_model = None
    if activity:
        activity_cfg = settings.parsed_activity_overrides.get(activity, {})
        activity_provider = activity_cfg.get("provider") or None
        activity_model = activity_cfg.get("model") or None

    # ── Provider ──────────────────────────────────────────────────
    resolved_provider = (
        provider or activity_provider or settings.default_provider or "ollama"
    )

    defaults = PROVIDER_DEFAULTS.get(resolved_provider, PROVIDER_DEFAULTS["ollama"])

    # ── Model ─────────────────────────────────────────────────────
    resolved_model = (
        model
        or activity_model
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
