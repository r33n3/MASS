"""Platform settings management.

Provides GET/PUT endpoints for platform-wide LLM defaults so the UI
can read and update the default provider, model, and API keys.

Settings are persisted to ``data/platform_settings.json`` (inside the
``./data:/app/data`` Docker volume) so they survive container restarts.
On startup the saved settings are loaded back into ``os.environ``.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from fastapi import HTTPException, status as http_status
from mass.api.dependencies import AdminDep, CurrentTenantDep

logger = logging.getLogger(__name__)

router = APIRouter()

# Persistent JSON file inside the mounted data volume
_SETTINGS_FILE = Path("/app/data/platform_settings.json")


# ── Schemas ───────────────────────────────────────────────────────────

class ActivityModelConfig(BaseModel):
    """Per-activity LLM model override.

    Leave fields as ``None`` (or empty string) to fall back to the
    platform-wide default provider / model.
    """

    provider: str | None = Field(None, description="Provider for this activity (empty = use global default)")
    model: str | None = Field(None, description="Model for this activity (empty = use provider default)")


class ActivityOverridesResponse(BaseModel):
    """Current per-activity model overrides."""

    chat: ActivityModelConfig = Field(default_factory=ActivityModelConfig)
    code_analysis: ActivityModelConfig = Field(default_factory=ActivityModelConfig)
    verdict: ActivityModelConfig = Field(default_factory=ActivityModelConfig)
    threat_model: ActivityModelConfig = Field(default_factory=ActivityModelConfig)
    explainability: ActivityModelConfig = Field(default_factory=ActivityModelConfig)
    guardrails: ActivityModelConfig = Field(default_factory=ActivityModelConfig)
    finding_verification: ActivityModelConfig = Field(default_factory=ActivityModelConfig)


class ActivityOverridesUpdate(BaseModel):
    """Update per-activity model overrides.

    Only include activities you want to change.  Omitted activities keep
    their current config.  Set provider/model to empty string to clear
    an override (revert to global default).
    """

    chat: ActivityModelConfig | None = None
    code_analysis: ActivityModelConfig | None = None
    verdict: ActivityModelConfig | None = None
    threat_model: ActivityModelConfig | None = None
    explainability: ActivityModelConfig | None = None
    guardrails: ActivityModelConfig | None = None
    finding_verification: ActivityModelConfig | None = None


class PlatformDefaultsResponse(BaseModel):
    """Current platform-wide LLM defaults."""

    default_provider: str = "ollama"
    default_model: str = ""
    has_openai_key: bool = False
    has_anthropic_key: bool = False
    has_google_key: bool = False
    has_grok_key: bool = False
    activity_overrides: ActivityOverridesResponse = Field(
        default_factory=ActivityOverridesResponse,
    )
    # Configurable directories
    targets_dir: str = Field(default="/app/targets", description="Static analysis targets directory")
    downloads_dir: str = Field(default="/app/downloads", description="Downloads/uploads directory")
    github_clones_dir: str = Field(default="/app/github_clones", description="GitHub clones directory")
    strategies_dir: str = Field(default="/app/data/strategies", description="Interrogation strategies directory")
    reports_dir: str = Field(default="/app/data/reports", description="Report output directory")
    sandbox_scenarios_dir: str = Field(default="/app/data/sandbox/scenarios", description="Sandbox scenarios directory")
    guardrails_export_dir: str = Field(default="/app/data/guardrails_export", description="Guardrails export directory")


class PlatformDefaultsUpdate(BaseModel):
    """Update platform-wide LLM defaults."""

    default_provider: str | None = Field(None, description="Default provider")
    default_model: str | None = Field(None, description="Default model (empty = provider default)")
    openai_api_key: str | None = Field(None, description="OpenAI API key")
    anthropic_api_key: str | None = Field(None, description="Anthropic API key")
    google_api_key: str | None = Field(None, description="Google/Gemini API key")
    grok_api_key: str | None = Field(None, description="Grok/xAI API key")
    activity_overrides: ActivityOverridesUpdate | None = Field(
        None, description="Per-activity model overrides",
    )
    # Configurable directories
    targets_dir: str | None = Field(None, description="Static analysis targets directory")
    downloads_dir: str | None = Field(None, description="Downloads/uploads directory")
    github_clones_dir: str | None = Field(None, description="GitHub clones directory")
    strategies_dir: str | None = Field(None, description="Interrogation strategies directory")
    reports_dir: str | None = Field(None, description="Report output directory")
    sandbox_scenarios_dir: str | None = Field(None, description="Sandbox scenarios directory")
    guardrails_export_dir: str | None = Field(None, description="Guardrails export directory")


# ── Persistent settings helpers ──────────────────────────────────────

def _settings_path() -> Path:
    """Return the path to the persistent settings JSON file."""
    # Inside Docker the data volume is at /app/data.
    # Outside Docker (local dev) fall back to ./data relative to CWD.
    for candidate in [_SETTINGS_FILE, Path("data/platform_settings.json")]:
        if candidate.parent.is_dir():
            return candidate
    # Last resort: create data dir at CWD
    Path("data").mkdir(exist_ok=True)
    return Path("data/platform_settings.json")


def _load_saved_settings() -> dict[str, str]:
    """Load settings from the persistent JSON file (empty dict on first run)."""
    path = _settings_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read settings file %s: %s", path, exc)
        return {}


def _save_settings(settings: dict[str, str]) -> None:
    """Write settings to the persistent JSON file."""
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")


def load_platform_settings_into_env() -> None:
    """Load saved platform settings into ``os.environ`` at startup.

    Called once during application init so that ``MassSettings`` (which
    reads from env vars) picks up the persisted values.
    """
    saved = _load_saved_settings()
    if not saved:
        return
    for key, value in saved.items():
        if value:  # Don't overwrite with empty strings
            os.environ[key] = value
    logger.info(
        "Loaded %d platform settings from %s: %s",
        len(saved), _settings_path(), list(saved.keys()),
    )


# ── Endpoints ─────────────────────────────────────────────────────────

@router.get(
    "/platform-defaults",
    response_model=PlatformDefaultsResponse,
    summary="Get platform-wide LLM defaults",
)
async def get_platform_defaults(tenant: CurrentTenantDep) -> PlatformDefaultsResponse:
    """Return current platform-wide LLM provider, model, and key status."""
    from mass.core.config import get_settings

    settings = get_settings()

    # Build per-activity overrides from the parsed JSON
    overrides = settings.parsed_activity_overrides
    activity_resp = ActivityOverridesResponse(
        chat=ActivityModelConfig(**(overrides.get("chat", {}))),
        code_analysis=ActivityModelConfig(**(overrides.get("code_analysis", {}))),
        verdict=ActivityModelConfig(**(overrides.get("verdict", {}))),
        threat_model=ActivityModelConfig(**(overrides.get("threat_model", {}))),
        explainability=ActivityModelConfig(**(overrides.get("explainability", {}))),
        guardrails=ActivityModelConfig(**(overrides.get("guardrails", {}))),
        finding_verification=ActivityModelConfig(**(overrides.get("finding_verification", {}))),
    )

    return PlatformDefaultsResponse(
        default_provider=settings.default_provider,
        default_model=settings.default_model,
        has_openai_key=bool(settings.openai_api_key.get_secret_value()),
        has_anthropic_key=bool(settings.anthropic_api_key.get_secret_value()),
        has_google_key=bool(settings.google_api_key.get_secret_value()),
        has_grok_key=bool(settings.grok_api_key.get_secret_value()),
        activity_overrides=activity_resp,
        targets_dir=settings.targets_dir,
        downloads_dir=settings.downloads_dir,
        github_clones_dir=settings.github_clones_dir,
        strategies_dir=settings.strategies_dir,
        reports_dir=settings.reports_dir,
        sandbox_scenarios_dir=settings.sandbox_scenarios_dir,
        guardrails_export_dir=settings.guardrails_export_dir,
    )


@router.put(
    "/platform-defaults",
    summary="Update platform-wide LLM defaults",
)
async def update_platform_defaults(
    update: PlatformDefaultsUpdate,
    tenant: AdminDep,
) -> dict[str, Any]:
    """Update platform defaults.

    Persists to ``data/platform_settings.json`` (survives container
    restarts) and updates ``os.environ`` so changes take effect
    immediately.  Requires admin privileges.
    """
    # Validate directory paths stay within /app/
    _SAFE_PREFIXES = ("/app/", "./")
    for field_name in (
        "targets_dir", "downloads_dir", "github_clones_dir",
        "strategies_dir", "reports_dir", "sandbox_scenarios_dir",
        "guardrails_export_dir",
    ):
        value = getattr(update, field_name, None)
        if value is not None:
            normalised = os.path.normpath(value)
            if ".." in normalised or not any(
                normalised.startswith(p) for p in _SAFE_PREFIXES
            ):
                raise HTTPException(
                    status_code=http_status.HTTP_400_BAD_REQUEST,
                    detail=f"Directory '{field_name}' must be under /app/. "
                           f"Got: {value}",
                )

    # Map update fields → env variable names
    updates: dict[str, str] = {}
    if update.default_provider is not None:
        updates["MASS_DEFAULT_PROVIDER"] = update.default_provider
    if update.default_model is not None:
        updates["MASS_DEFAULT_MODEL"] = update.default_model
    if update.openai_api_key is not None:
        updates["MASS_OPENAI_API_KEY"] = update.openai_api_key
    if update.anthropic_api_key is not None:
        updates["MASS_ANTHROPIC_API_KEY"] = update.anthropic_api_key
    if update.google_api_key is not None:
        updates["MASS_GOOGLE_API_KEY"] = update.google_api_key
    if update.grok_api_key is not None:
        updates["MASS_GROK_API_KEY"] = update.grok_api_key

    # Configurable directories
    if update.targets_dir is not None:
        updates["MASS_TARGETS_DIR"] = update.targets_dir
    if update.downloads_dir is not None:
        updates["MASS_DOWNLOADS_DIR"] = update.downloads_dir
    if update.github_clones_dir is not None:
        updates["MASS_GITHUB_CLONES_DIR"] = update.github_clones_dir
    if update.strategies_dir is not None:
        updates["MASS_STRATEGIES_DIR"] = update.strategies_dir
    if update.reports_dir is not None:
        updates["MASS_REPORTS_DIR"] = update.reports_dir
    if update.sandbox_scenarios_dir is not None:
        updates["MASS_SANDBOX_SCENARIOS_DIR"] = update.sandbox_scenarios_dir
    if update.guardrails_export_dir is not None:
        updates["MASS_GUARDRAILS_EXPORT_DIR"] = update.guardrails_export_dir

    # Handle per-activity model overrides
    if update.activity_overrides is not None:
        saved_for_overrides = _load_saved_settings()
        current_overrides: dict[str, dict[str, str]] = {}
        try:
            raw = saved_for_overrides.get("MASS_ACTIVITY_OVERRIDES", "{}")
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                current_overrides = parsed
        except (json.JSONDecodeError, TypeError):
            pass

        for activity_name in (
            "chat", "code_analysis", "verdict", "threat_model",
            "explainability", "guardrails", "finding_verification",
        ):
            activity_update = getattr(update.activity_overrides, activity_name, None)
            if activity_update is not None:
                cfg: dict[str, str] = {}
                if activity_update.provider:
                    cfg["provider"] = activity_update.provider
                if activity_update.model:
                    cfg["model"] = activity_update.model
                current_overrides[activity_name] = cfg

        updates["MASS_ACTIVITY_OVERRIDES"] = json.dumps(current_overrides)

    if not updates:
        return {"message": "No changes provided"}

    # Merge with existing saved settings and persist to JSON file
    saved = _load_saved_settings()
    saved.update(updates)
    _save_settings(saved)

    # Also set in current process environment so changes take effect now
    for key, value in updates.items():
        os.environ[key] = value

    # Clear MassSettings cache so next get_settings() reads fresh values
    from mass.core.config import get_settings
    get_settings.cache_clear()

    logger.info("Platform defaults updated and persisted: %s", list(updates.keys()))

    return {
        "message": "Platform defaults updated",
        "updated": list(updates.keys()),
    }
