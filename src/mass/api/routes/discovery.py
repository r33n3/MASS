"""Discovery endpoints.

Provides lightweight reconnaissance of deployment targets before scanning.
Identifies AI components, models, frameworks, and recommends scan configuration.
"""

import hashlib
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from mass.api.dependencies import CurrentTenantDep
from mass.api.schemas.discovery import (
    DiscoveryRequest,
    DiscoveryResponse,
    DiscoveredComponent,
    DiscoveredDependency,
    ScanRecommendation,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Base directory for mounted scan targets inside Docker
TARGETS_BASE = Path("/app/targets")
GITHUB_CLONES_DIR = TARGETS_BASE / "_github_clones"


def _is_github_url(path: str) -> bool:
    """Check if path is a GitHub URL."""
    return path.startswith("https://github.com/") or path.startswith("git@github.com:")


def _clone_github_repo(url: str) -> Path:
    """Clone a GitHub repo to a local directory.

    Returns the path to the cloned repo. Uses a hash-based directory name
    to allow re-use of existing clones.
    """
    # Normalize URL
    if url.endswith(".git"):
        url = url[:-4]
    url = url.rstrip("/")

    # Extract repo name from URL
    parts = url.split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid GitHub URL: {url}")
    repo_name = parts[-1]
    owner = parts[-2]

    # Create a unique but stable directory name
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    clone_dir = GITHUB_CLONES_DIR / f"{owner}_{repo_name}_{url_hash}"

    # Ensure clones directory exists
    GITHUB_CLONES_DIR.mkdir(parents=True, exist_ok=True)

    # If already cloned, pull latest
    if clone_dir.exists() and (clone_dir / ".git").exists():
        logger.info(f"Updating existing clone: {clone_dir}")
        try:
            subprocess.run(
                ["git", "-C", str(clone_dir), "pull", "--ff-only"],
                capture_output=True,
                timeout=60,
            )
        except Exception as e:
            logger.warning(f"Failed to update clone: {e}")
        return clone_dir

    # Remove partial clone if exists
    if clone_dir.exists():
        shutil.rmtree(clone_dir)

    # Clone the repo
    logger.info(f"Cloning {url} to {clone_dir}")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(clone_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr}")
    except subprocess.TimeoutExpired:
        if clone_dir.exists():
            shutil.rmtree(clone_dir)
        raise RuntimeError("Clone timed out after 120 seconds")
    except FileNotFoundError:
        raise RuntimeError("git is not installed")

    return clone_dir


def _translate_path(raw_path: str) -> tuple[Path, str | None]:
    """Translate a host path to a Docker-accessible path.

    Handles:
    - GitHub URLs: Clones the repo and returns the clone path
    - Windows paths (C:\\Users\\... or C:/Users/...): Maps to mounted targets
    - Docker paths (/app/targets/...): Uses directly

    Returns:
        Tuple of (resolved_path, error_message). If error_message is set, the path is invalid.
    """
    # Handle GitHub URLs
    if _is_github_url(raw_path):
        try:
            clone_path = _clone_github_repo(raw_path)
            return clone_path, None
        except Exception as e:
            return Path(raw_path), f"Failed to clone GitHub repo: {e}"

    p = Path(raw_path)
    if p.exists():
        return p, None

    # Normalise Windows separators
    normalised = raw_path.replace("\\", "/")

    # Try to match against mounted targets by walking up the path
    parts = normalised.rstrip("/").split("/")
    if TARGETS_BASE.is_dir():
        available = {d.name.lower(): d for d in TARGETS_BASE.iterdir() if d.is_dir()}
        # Walk from the end to find the deepest match
        for i, part in enumerate(parts):
            if part.lower() in available:
                # Reconstruct the remaining sub-path
                remainder = "/".join(parts[i + 1:]) if i + 1 < len(parts) else ""
                translated = available[part.lower()]
                if remainder:
                    translated = translated / remainder
                return translated, None

    # Path not found - provide helpful error
    if normalised.startswith("/app/targets"):
        available_list = [d.name for d in TARGETS_BASE.iterdir() if d.is_dir()] if TARGETS_BASE.is_dir() else []
        return p, f"Path not found inside container. Available targets: {', '.join(available_list) or 'none'}"
    elif ":" in normalised or normalised.startswith("/"):
        # Looks like a local path
        available_list = [d.name for d in TARGETS_BASE.iterdir() if d.is_dir()] if TARGETS_BASE.is_dir() else []
        return p, (
            f"Local path not accessible. Paths must be mounted into the container. "
            f"Available targets: {', '.join(available_list) or 'none'}. "
            f"Tip: Use a GitHub URL like https://github.com/owner/repo"
        )

    return p, None


class TargetEntry(BaseModel):
    """Available scan target directory."""
    name: str
    path: str
    file_count: int = 0
    has_models: bool = False
    has_code: bool = False
    source: str = "local"  # "local" or "github"


@router.get(
    "/targets",
    response_model=list[TargetEntry],
    summary="List available scan targets",
    description=(
        "Lists directories mounted under /app/targets/ that are available "
        "for discovery and scanning. Use these paths in discovery and "
        "scan-target requests."
    ),
)
async def list_targets(tenant: CurrentTenantDep) -> list[TargetEntry]:
    """List available mounted target directories and GitHub clones."""
    targets: list[TargetEntry] = []

    def _scan_entry(entry: Path, source: str = "local") -> TargetEntry | None:
        if not entry.is_dir():
            return None
        file_count = 0
        has_models = False
        has_code = False
        try:
            for dirpath, dirnames, filenames in os.walk(str(entry), topdown=True):
                dirnames[:] = [
                    d for d in dirnames
                    if d not in EXCLUDED_DIRS and not d.endswith(".egg-info")
                ]
                for fn in filenames:
                    file_count += 1
                    ext = os.path.splitext(fn)[1].lower()
                    if ext in MODEL_EXTENSIONS:
                        has_models = True
                    if ext in {".py", ".js", ".ts", ".jsx", ".tsx"}:
                        has_code = True
                    if file_count > 5000:
                        break
                if file_count > 5000:
                    break
        except PermissionError:
            pass
        return TargetEntry(
            name=entry.name,
            path=str(entry),
            file_count=file_count,
            has_models=has_models,
            has_code=has_code,
            source=source,
        )

    if not TARGETS_BASE.is_dir():
        return targets

    # List mounted targets (excluding _github_clones)
    for entry in sorted(TARGETS_BASE.iterdir()):
        if entry.name.startswith("_"):
            continue
        target = _scan_entry(entry, "local")
        if target:
            targets.append(target)

    # List GitHub clones
    if GITHUB_CLONES_DIR.is_dir():
        for entry in sorted(GITHUB_CLONES_DIR.iterdir()):
            target = _scan_entry(entry, "github")
            if target:
                targets.append(target)

    return targets

# Known AI/ML frameworks to detect in dependencies
AI_FRAMEWORKS = {
    "langchain", "langchain-core", "langchain-community", "langgraph",
    "openai", "anthropic", "cohere", "huggingface-hub",
    "transformers", "torch", "pytorch", "tensorflow", "keras", "jax",
    "crewai", "autogen", "llama-index", "llamaindex",
    "chromadb", "pinecone-client", "weaviate-client", "qdrant-client",
    "sentence-transformers", "tiktoken", "tokenizers",
    "gradio", "streamlit",
    "ollama", "llama-cpp-python", "ctransformers",
    "diffusers", "accelerate", "peft", "trl",
    "guidance", "dspy-ai", "instructor",
    "mcp",
    # MCP (Model Context Protocol) packages
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-node",
    "@modelcontextprotocol/server-deno",
    "mcp-python",
    "mcp-sdk",
}

# MCP-related packages for detection
MCP_PACKAGES = {
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-node",
    "@modelcontextprotocol/server-deno",
    "mcp-python",
    "mcp-sdk",
    "mcp",
}

# Model file extensions
MODEL_EXTENSIONS = {
    ".gguf", ".pt", ".pth", ".bin", ".safetensors",
    ".onnx", ".pb", ".h5", ".keras", ".tflite",
    ".mlmodel", ".pkl", ".joblib",
}

# Directories to exclude (same as ScanService)
EXCLUDED_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "build", "dist", "eggs",
    "llama.cpp", "sd.cpp", "whisper.cpp",
    "bin", "obj", "target", "out",
    "vendor", "third_party", "external",
}


@router.post(
    "",
    response_model=DiscoveryResponse,
    summary="Discover deployment components",
    description=(
        "Performs lightweight reconnaissance on a deployment target. "
        "Identifies AI components, models, frameworks, and recommends "
        "the appropriate scan profile. Run this before scanning to "
        "understand scope and avoid scanning irrelevant files."
    ),
)
async def discover_deployment(
    request: DiscoveryRequest,
    tenant: CurrentTenantDep,
) -> DiscoveryResponse:
    """Discover components in a deployment target."""
    import fnmatch

    target_path, error = _translate_path(request.path)
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error,
        )
    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Path not found: {request.path}",
        )

    # For single files, discover the parent directory
    if target_path.is_file():
        target_path = target_path.parent

    if not target_path.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path must be a directory or file",
        )

    # Walk once with exclusions
    all_files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(str(target_path), topdown=True):
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDED_DIRS and not d.endswith(".egg-info")
        ]
        rel_dir = os.path.relpath(dirpath, str(target_path))
        for filename in filenames:
            if rel_dir == ".":
                all_files.append(filename)
            else:
                all_files.append(f"{rel_dir}/{filename}".replace("\\", "/"))

    # Run component discovery
    from mass.analyzers.deployment.discovery import ComponentDiscovery
    discovery = ComponentDiscovery()
    components_raw, dependencies_raw = discovery.discover(target_path)

    # Build components list
    components: list[DiscoveredComponent] = []
    components_by_type: dict[str, int] = {}
    for comp in components_raw:
        comp_type = comp.component_type if hasattr(comp, 'component_type') else "unknown"
        comp_name = comp.name if hasattr(comp, 'name') else str(comp)
        comp_path = str(comp.path) if hasattr(comp, 'path') else ""
        comp_size = comp.size if hasattr(comp, 'size') else 0

        components_by_type[comp_type] = components_by_type.get(comp_type, 0) + 1

        if len(components) < 200:  # Truncate to avoid huge responses
            components.append(DiscoveredComponent(
                name=comp_name,
                component_type=comp_type,
                file_path=comp_path,
                size_bytes=comp_size,
            ))

    # Build dependencies list and detect AI frameworks
    dependencies: list[DiscoveredDependency] = []
    ai_frameworks_found: list[str] = []
    for dep_name, dep_info in dependencies_raw.items():
        version = dep_info.version if hasattr(dep_info, 'version') else None
        source = dep_info.source if hasattr(dep_info, 'source') else "unknown"
        is_ai = dep_name.lower() in AI_FRAMEWORKS

        if is_ai:
            ai_frameworks_found.append(dep_name)

        dependencies.append(DiscoveredDependency(
            name=dep_name,
            version=version,
            source=source,
            is_ai_framework=is_ai,
        ))

    # Find model files from the file index
    model_files: list[str] = []
    for rel_path in all_files:
        filename = rel_path.rsplit("/", 1)[-1] if "/" in rel_path else rel_path
        dot_idx = filename.rfind(".")
        if dot_idx >= 0 and filename[dot_idx:].lower() in MODEL_EXTENSIONS:
            model_files.append(rel_path)

    # Detect capabilities from file index
    def has_files(*patterns: str) -> bool:
        for fp in all_files:
            fn = (fp.rsplit("/", 1)[-1] if "/" in fp else fp).lower()
            for p in patterns:
                if fnmatch.fnmatch(fn, p.lower()):
                    return True
        return False

    has_models = len(model_files) > 0
    has_context = has_files("*prompt*", "*context*", "*system*", "*instruct*")
    # Check for MCP both in file names and dependencies
    has_mcp_files = has_files("*mcp*", "*server*.ts", "*server*.py")
    mcp_deps = [d for d in dependencies_raw.keys() if d.lower() in MCP_PACKAGES]
    has_mcp = has_mcp_files or len(mcp_deps) > 0
    has_workflows = has_files("*agent*.py", "*workflow*.py", "*chain*.py", "*graph*.py")
    has_infrastructure = has_files("Dockerfile*", "docker-compose*", "*.tf")
    has_secrets_risk = has_files("*.env", "*.env.*", "*.cfg", "*.ini", "*.conf")

    # Build scan recommendation
    if has_mcp:
        profile = "comprehensive"
        mcp_tools = [d for d in dependencies_raw.keys() if d.lower() in MCP_PACKAGES]
        reason = (
            f"MCP server detected ({', '.join(mcp_tools) or 'mcp-server files'}). "
            f"Comprehensive scan recommended for tool injection analysis and security review. "
            f"Consider running model interrogation to test tool invocation security."
        )
    elif has_models and ai_frameworks_found and has_workflows:
        profile = "comprehensive"
        reason = (
            f"Complex AI deployment with {len(model_files)} model file(s), "
            f"{len(ai_frameworks_found)} AI framework(s), and agent workflows"
        )
    elif ai_frameworks_found or has_models:
        profile = "standard"
        reason = (
            f"AI deployment with {len(ai_frameworks_found)} framework(s) and "
            f"{len(model_files)} model file(s)"
        )
    else:
        profile = "quick"
        reason = "No AI models or frameworks detected - quick scan for secrets and config issues"

    recommendation = ScanRecommendation(
        recommended_profile=profile,
        reason=reason,
        estimated_files=len(all_files),
        has_models=has_models,
        has_context=has_context,
        has_mcp=has_mcp,
        has_workflows=has_workflows,
        has_infrastructure=has_infrastructure,
        has_secrets_risk=has_secrets_risk,
    )

    logger.info(
        f"Discovery completed: {len(all_files)} files, "
        f"{len(components_raw)} components, "
        f"{len(ai_frameworks_found)} AI frameworks, "
        f"recommended profile: {profile}"
    )

    return DiscoveryResponse(
        path=str(target_path),
        total_files=len(all_files),
        total_components=len(components_raw),
        components_by_type=components_by_type,
        ai_frameworks=ai_frameworks_found,
        model_files=model_files[:50],  # Truncate model files list
        components=components,
        dependencies=dependencies,
        recommendation=recommendation,
    )
