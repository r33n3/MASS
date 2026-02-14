"""Platform settings management.

Provides GET/PUT endpoints for platform-wide LLM defaults so the UI
can read and update the default provider, model, and API keys without
editing .env files manually.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from mass.api.dependencies import CurrentTenantDep

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────

class PlatformDefaultsResponse(BaseModel):
    """Current platform-wide LLM defaults."""

    default_provider: str = "ollama"
    default_model: str = ""
    has_openai_key: bool = False
    has_anthropic_key: bool = False
    has_google_key: bool = False
    has_grok_key: bool = False


class PlatformDefaultsUpdate(BaseModel):
    """Update platform-wide LLM defaults."""

    default_provider: str | None = Field(None, description="Default provider")
    default_model: str | None = Field(None, description="Default model (empty = provider default)")
    openai_api_key: str | None = Field(None, description="OpenAI API key")
    anthropic_api_key: str | None = Field(None, description="Anthropic API key")
    google_api_key: str | None = Field(None, description="Google/Gemini API key")
    grok_api_key: str | None = Field(None, description="Grok/xAI API key")


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
    return PlatformDefaultsResponse(
        default_provider=settings.default_provider,
        default_model=settings.default_model,
        has_openai_key=bool(settings.openai_api_key.get_secret_value()),
        has_anthropic_key=bool(settings.anthropic_api_key.get_secret_value()),
        has_google_key=bool(settings.google_api_key.get_secret_value()),
        has_grok_key=bool(settings.grok_api_key.get_secret_value()),
    )


@router.put(
    "/platform-defaults",
    summary="Update platform-wide LLM defaults",
)
async def update_platform_defaults(
    update: PlatformDefaultsUpdate,
    tenant: CurrentTenantDep,
) -> dict[str, Any]:
    """Update platform defaults by writing to the .env file.

    Changes take effect immediately (MassSettings cache is cleared).
    """
    env_path = _find_env_file()

    # Map update fields → .env variable names
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

    if not updates:
        return {"message": "No changes provided"}

    # Write to .env file
    _update_env_file(env_path, updates)

    # Also set in current process environment so changes take effect now
    for key, value in updates.items():
        os.environ[key] = value

    # Clear MassSettings cache so next get_settings() reads fresh values
    from mass.core.config import get_settings
    get_settings.cache_clear()

    logger.info("Platform defaults updated: %s", list(updates.keys()))

    return {
        "message": "Platform defaults updated",
        "updated": list(updates.keys()),
    }


# ── Helpers ───────────────────────────────────────────────────────────

def _find_env_file() -> Path:
    """Locate the .env file."""
    # Check common locations
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[4] / ".env",  # src/mass/api/routes → project root
    ]
    for p in candidates:
        if p.is_file():
            return p

    # Create at CWD if none exists
    env_path = Path.cwd() / ".env"
    env_path.touch()
    return env_path


def _update_env_file(env_path: Path, updates: dict[str, str]) -> None:
    """Update or append key=value pairs in a .env file.

    Preserves comments and ordering. Updates existing keys in-place,
    appends new keys at the end.
    """
    lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
    remaining = dict(updates)  # Keys not yet found in existing lines

    new_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            # Check if it's a commented-out version of a key we're updating
            for key in list(remaining.keys()):
                if stripped == f"# {key}=" or stripped.startswith(f"# {key}="):
                    # Uncomment and set value
                    new_lines.append(f"{key}={remaining.pop(key)}\n")
                    break
            else:
                new_lines.append(line if line.endswith("\n") else line + "\n")
            continue

        # Parse key=value
        if "=" in stripped:
            env_key = stripped.split("=", 1)[0].strip()
            if env_key in remaining:
                new_lines.append(f"{env_key}={remaining.pop(env_key)}\n")
                continue

        new_lines.append(line if line.endswith("\n") else line + "\n")

    # Append any keys not found in existing file
    if remaining:
        if new_lines and not new_lines[-1].strip() == "":
            new_lines.append("\n")
        for key, value in remaining.items():
            new_lines.append(f"{key}={value}\n")

    env_path.write_text("".join(new_lines), encoding="utf-8")
