"""File browser endpoints for scan target selection.

Provides a server-side directory browser so users can navigate
the container filesystem to select scan targets.

Also provides model file discovery using magic number detection.
"""

import os
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from mass.api.dependencies import CurrentTenantDep
from mass.analyzers.model_file.magic import identify_file, MagicSignature

router = APIRouter()


class FileEntry(BaseModel):
    """A file or directory entry."""
    name: str
    path: str
    is_dir: bool
    size: int = 0
    extension: str = ""


class BrowseResponse(BaseModel):
    """Response from browsing a directory."""
    current_path: str
    parent_path: str | None
    entries: list[FileEntry]
    can_scan: bool = Field(
        description="Whether this directory can be scanned (has code files)"
    )


# Allowed root paths for browsing (security)
ALLOWED_ROOTS = [
    "/app/targets",
    "/app/data",
    "/app/src",
]

# File extensions that indicate scannable content
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".env",
    ".md", ".txt", ".gguf", ".onnx", ".safetensors",
}


def is_path_allowed(path: str) -> bool:
    """Check if path is within allowed roots."""
    abs_path = os.path.abspath(path)
    return any(abs_path.startswith(root) for root in ALLOWED_ROOTS)


@router.get(
    "",
    response_model=BrowseResponse,
    summary="Browse directory",
    description="List contents of a directory for scan target selection.",
)
async def browse_directory(
    tenant: CurrentTenantDep,
    path: Annotated[str, Query(description="Directory path to browse")] = "/app/targets",
) -> BrowseResponse:
    """Browse a directory on the server filesystem."""
    # Normalize and validate path
    try:
        abs_path = os.path.abspath(path)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid path",
        )

    # Security check - only allow browsing within allowed roots
    if not is_path_allowed(abs_path):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. Allowed paths: {', '.join(ALLOWED_ROOTS)}",
        )

    if not os.path.exists(abs_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Path not found: {path}",
        )

    if not os.path.isdir(abs_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path is not a directory",
        )

    # List directory contents
    entries: list[FileEntry] = []
    has_scannable = False

    try:
        for entry in sorted(os.listdir(abs_path)):
            # Skip hidden files and common non-essential dirs
            if entry.startswith(".") or entry in ("__pycache__", "node_modules", ".git", "venv", ".venv"):
                continue

            entry_path = os.path.join(abs_path, entry)
            is_dir = os.path.isdir(entry_path)

            try:
                size = os.path.getsize(entry_path) if not is_dir else 0
            except OSError:
                size = 0

            ext = Path(entry).suffix.lower() if not is_dir else ""

            if ext in SCANNABLE_EXTENSIONS or is_dir:
                has_scannable = True

            entries.append(FileEntry(
                name=entry,
                path=entry_path,
                is_dir=is_dir,
                size=size,
                extension=ext,
            ))

    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied",
        )

    # Sort: directories first, then files
    entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))

    # Compute parent path
    parent = os.path.dirname(abs_path)
    parent_path = parent if is_path_allowed(parent) else None

    return BrowseResponse(
        current_path=abs_path,
        parent_path=parent_path,
        entries=entries,
        can_scan=has_scannable,
    )


@router.get(
    "/roots",
    response_model=list[str],
    summary="Get browsable root paths",
)
async def get_browse_roots(tenant: CurrentTenantDep) -> list[str]:
    """Get list of root paths available for browsing."""
    # Return only roots that actually exist
    return [root for root in ALLOWED_ROOTS if os.path.exists(root)]


class ModelFileEntry(BaseModel):
    """A discovered model file."""
    name: str
    path: str
    size: int
    format_name: str
    description: str
    risk_level: str


class ModelDiscoveryResponse(BaseModel):
    """Response from model file discovery."""
    scan_path: str
    total_files_scanned: int
    model_files: list[ModelFileEntry]
    by_format: dict[str, int] = Field(description="Count of files by format")
    by_risk: dict[str, int] = Field(description="Count of files by risk level")


@router.get(
    "/models",
    response_model=ModelDiscoveryResponse,
    summary="Discover model files",
    description="Scan a directory tree for model files using magic number detection.",
)
async def discover_model_files(
    tenant: CurrentTenantDep,
    path: Annotated[str, Query(description="Directory to scan")] = "/app/targets",
    max_depth: Annotated[int, Query(ge=1, le=10, description="Max directory depth")] = 5,
    max_files: Annotated[int, Query(ge=1, le=10000, description="Max files to scan")] = 1000,
) -> ModelDiscoveryResponse:
    """Discover model files in a directory using magic number fingerprinting.

    Scans for:
    - GGUF (quantized LLMs)
    - Safetensors (HuggingFace)
    - Pickle/PyTorch checkpoints (CRITICAL risk - arbitrary code execution)
    - ONNX models
    - HDF5/Keras models
    - TensorFlow Lite
    """
    # Validate path
    try:
        abs_path = os.path.abspath(path)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid path",
        )

    if not is_path_allowed(abs_path):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. Allowed paths: {', '.join(ALLOWED_ROOTS)}",
        )

    if not os.path.exists(abs_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Path not found: {path}",
        )

    model_files: list[ModelFileEntry] = []
    by_format: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    files_scanned = 0

    # Walk directory tree
    for root, dirs, files in os.walk(abs_path):
        # Check depth
        depth = root[len(abs_path):].count(os.sep)
        if depth >= max_depth:
            dirs.clear()  # Don't descend further
            continue

        # Skip common non-model directories and inaccessible ones
        accessible_dirs = []
        for d in dirs:
            if d in ("__pycache__", "node_modules", ".git", "venv", ".venv",
                     ".cache", ".npm", ".pip", "dist", "build"):
                continue
            dir_path = os.path.join(root, d)
            try:
                os.listdir(dir_path)  # Test access
                accessible_dirs.append(d)
            except PermissionError:
                continue  # Skip inaccessible directories
        dirs[:] = accessible_dirs

        for filename in files:
            if files_scanned >= max_files:
                break

            file_path = os.path.join(root, filename)

            # Skip files we can't access
            try:
                if not os.access(file_path, os.R_OK):
                    continue
            except OSError:
                continue

            files_scanned += 1

            # Use magic number detection
            sig = identify_file(file_path)

            if sig and sig.is_model:
                try:
                    size = os.path.getsize(file_path)
                except OSError:
                    size = 0

                model_files.append(ModelFileEntry(
                    name=filename,
                    path=file_path,
                    size=size,
                    format_name=sig.format_name,
                    description=sig.description,
                    risk_level=sig.risk_level,
                ))

                # Update counts
                by_format[sig.format_name] = by_format.get(sig.format_name, 0) + 1
                by_risk[sig.risk_level] = by_risk.get(sig.risk_level, 0) + 1

        if files_scanned >= max_files:
            break

    # Sort by risk level (critical first) then by size (largest first)
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
    model_files.sort(key=lambda m: (risk_order.get(m.risk_level, 5), -m.size))

    return ModelDiscoveryResponse(
        scan_path=abs_path,
        total_files_scanned=files_scanned,
        model_files=model_files,
        by_format=by_format,
        by_risk=by_risk,
    )
