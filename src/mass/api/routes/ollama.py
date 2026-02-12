"""Ollama model management endpoints.

Load GGUF files into Ollama, list loaded models, and delete models.
"""

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from mass.api.dependencies import CurrentTenantDep
from mass.api.services.ollama_manager import (
    check_health,
    create_from_gguf,
    delete_model,
    get_ollama_hosts,
    list_models,
    sanitize_model_name,
    show_model,
)
from mass.api.routes.browse import is_path_allowed

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────

class OllamaLoadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gguf_path: str = Field(..., description="Path to GGUF file (container path)")
    model_name: str | None = Field(
        default=None,
        description="Custom model name (auto-generated from filename if omitted)",
    )
    system_prompt: str | None = Field(
        default=None,
        description="System prompt to embed in the model",
    )
    parameters: dict[str, Any] | None = Field(
        default=None,
        description="Ollama parameters (num_ctx, temperature, etc.)",
    )
    instance: str = Field(
        default="destination",
        description="Ollama instance: destination or source",
    )


class OllamaLoadResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool
    model_name: str
    message: str
    instance: str
    ollama_endpoint: str = Field(description="Ollama endpoint URL for interrogation")


class OllamaModelInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    size: str = ""
    modified: str = ""
    instance: str = "destination"


class OllamaModelsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination_healthy: bool
    source_healthy: bool
    models: list[OllamaModelInfo]


class OllamaDeleteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool
    message: str


class OllamaStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination: dict[str, Any]
    source: dict[str, Any]


# ── Helpers ──────────────────────────────────────────────────────────

def _resolve_gguf_path(raw_path: str) -> tuple[str, str | None]:
    """Resolve a path to a specific GGUF file.

    If path is a directory, find the .gguf file(s) in it.
    Validates the file exists and is within allowed roots.

    Returns:
        Tuple of (resolved_path, error_message).
    """
    p = Path(raw_path.strip().strip('"').strip("'"))

    if p.is_file():
        if p.suffix.lower() != ".gguf":
            return "", f"File is not a GGUF file: {p.name}"
        return str(p), None

    if p.is_dir():
        gguf_files = sorted(p.glob("*.gguf"))
        if not gguf_files:
            # Check subdirectories one level deep
            gguf_files = sorted(p.glob("**/*.gguf"))
        if not gguf_files:
            return "", f"No GGUF files found in {p}"
        if len(gguf_files) > 1:
            names = [f.name for f in gguf_files[:5]]
            return "", (
                f"Multiple GGUF files found: {', '.join(names)}. "
                "Please specify the exact file path."
            )
        return str(gguf_files[0]), None

    return "", f"Path not found: {p}"


def _format_size(size_bytes: int) -> str:
    """Format bytes as human-readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


# ── Endpoints ────────────────────────────────────────────────────────

@router.post(
    "/load",
    response_model=OllamaLoadResponse,
    summary="Load a GGUF model into Ollama",
    description="Create an Ollama model from a local GGUF file with optional system prompt.",
)
async def load_gguf_model(
    request: OllamaLoadRequest,
    tenant: CurrentTenantDep,
) -> OllamaLoadResponse:
    """Load a GGUF file into an Ollama instance."""
    hosts = get_ollama_hosts()
    instance = request.instance
    if instance not in hosts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid instance: {instance}. Use 'destination' or 'source'.",
        )
    host_url = hosts[instance]

    # Resolve the GGUF path
    resolved, error = _resolve_gguf_path(request.gguf_path)
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    # Security: validate path is within allowed roots
    abs_path = os.path.abspath(resolved)
    if not is_path_allowed(abs_path):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Path is outside allowed directories",
        )

    # Derive model name from filename if not provided
    model_name = request.model_name
    if not model_name:
        model_name = sanitize_model_name(Path(resolved).stem)

    # Check Ollama health
    healthy = await check_health(host_url)
    if not healthy:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Ollama ({instance}) is not reachable at {host_url}",
        )

    # Create the model
    success, message = await create_from_gguf(
        host_url=host_url,
        model_name=model_name,
        gguf_path=resolved,
        system_prompt=request.system_prompt,
        parameters=request.parameters,
        instance=instance,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )

    return OllamaLoadResponse(
        success=True,
        model_name=model_name,
        message=message,
        instance=instance,
        ollama_endpoint=host_url,
    )


@router.get(
    "/models",
    response_model=OllamaModelsResponse,
    summary="List all Ollama models",
    description="List models loaded on both destination and source Ollama instances.",
)
async def list_all_models(tenant: CurrentTenantDep) -> OllamaModelsResponse:
    """List models on both Ollama instances."""
    hosts = get_ollama_hosts()
    models: list[OllamaModelInfo] = []

    dest_healthy = await check_health(hosts["destination"])
    src_healthy = await check_health(hosts["source"])

    for role, host_url in hosts.items():
        try:
            raw_models = await list_models(host_url)
            for m in raw_models:
                size_bytes = m.get("size", 0)
                models.append(OllamaModelInfo(
                    name=m.get("name", "unknown"),
                    size=_format_size(size_bytes) if size_bytes else "",
                    modified=m.get("modified_at", ""),
                    instance=role,
                ))
        except Exception as e:
            logger.warning("Failed to list models from %s (%s): %s", role, host_url, e)

    return OllamaModelsResponse(
        destination_healthy=dest_healthy,
        source_healthy=src_healthy,
        models=models,
    )


@router.delete(
    "/models/{model_name:path}",
    response_model=OllamaDeleteResponse,
    summary="Delete an Ollama model",
)
async def delete_ollama_model(
    model_name: str,
    tenant: CurrentTenantDep,
    instance: str = Query(default="destination", description="Ollama instance"),
) -> OllamaDeleteResponse:
    """Delete a model from an Ollama instance."""
    hosts = get_ollama_hosts()
    if instance not in hosts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid instance: {instance}",
        )

    success, message = await delete_model(hosts[instance], model_name)
    return OllamaDeleteResponse(success=success, message=message)


@router.get(
    "/status",
    response_model=OllamaStatusResponse,
    summary="Ollama instance status",
)
async def ollama_status(tenant: CurrentTenantDep) -> OllamaStatusResponse:
    """Check health of both Ollama instances."""
    hosts = get_ollama_hosts()
    dest_healthy = await check_health(hosts["destination"])
    src_healthy = await check_health(hosts["source"])

    dest_models = await list_models(hosts["destination"]) if dest_healthy else []
    src_models = await list_models(hosts["source"]) if src_healthy else []

    return OllamaStatusResponse(
        destination={
            "healthy": dest_healthy,
            "url": hosts["destination"],
            "model_count": len(dest_models),
            "models": [m.get("name", "") for m in dest_models],
        },
        source={
            "healthy": src_healthy,
            "url": hosts["source"],
            "model_count": len(src_models),
            "models": [m.get("name", "") for m in src_models],
        },
    )
