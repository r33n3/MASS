"""Shared filesystem constants and helpers for target discovery.

Single source of truth for directory exclusions, model file extensions,
AI framework detection, and common filesystem walking patterns used
across scanning, discovery, and target enumeration.
"""

import os
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Directory exclusions — prune these during os.walk to avoid scanning
# build artifacts, vendored dependencies, and compiled runtimes.
# ---------------------------------------------------------------------------

EXCLUDED_DIRS: set[str] = {
    # Version control
    ".git", ".svn", ".hg",
    # Python caches / tooling
    "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    # Coverage artifacts
    "coverage", ".coverage", "htmlcov",
    # Build / distribution artifacts
    "build", "dist", "eggs",
    # JS / Node
    "node_modules",
    # Native/compiled ML runtimes (not the model files themselves)
    "llama.cpp", "sd.cpp", "whisper.cpp",
    # Binary/compiled output
    "bin", "obj", "target", "out",
    # Vendored/downloaded dependencies
    "vendor", "third_party", "external",
    # Large framework-specific directories
    "framepack_cu126_torch26",
    # Package cache directories
    ".cache", ".npm", ".pip",
}

# ---------------------------------------------------------------------------
# Model file extensions — used to detect ML model files during scanning.
# ---------------------------------------------------------------------------

MODEL_EXTENSIONS: set[str] = {
    ".gguf",          # llama.cpp quantized
    ".pt", ".pth",    # PyTorch
    ".bin",           # Generic binary / HuggingFace
    ".safetensors",   # Safe Tensors format
    ".onnx",          # ONNX Runtime
    ".pb",            # TensorFlow protobuf
    ".h5", ".keras",  # Keras / TensorFlow saved
    ".tflite",        # TensorFlow Lite
    ".mlmodel",       # CoreML
    ".pkl", ".joblib",  # Scikit-learn / pickle
}

# Source code extensions for quick detection
CODE_EXTENSIONS: set[str] = {".py", ".js", ".ts", ".jsx", ".tsx"}

# ---------------------------------------------------------------------------
# AI/ML framework detection — matched against dependency manifests
# (requirements.txt, pyproject.toml, package.json).
# ---------------------------------------------------------------------------

AI_FRAMEWORKS: set[str] = {
    # LLM orchestration
    "langchain", "langchain-core", "langchain-community", "langgraph",
    # LLM providers
    "openai", "anthropic", "cohere", "huggingface-hub",
    # ML frameworks
    "transformers", "torch", "pytorch", "tensorflow", "keras", "jax",
    # Agent frameworks
    "crewai", "autogen", "llama-index", "llamaindex",
    # Vector stores
    "chromadb", "pinecone-client", "weaviate-client", "qdrant-client",
    # Tokenizers
    "sentence-transformers", "tiktoken", "tokenizers",
    # UI frameworks
    "gradio", "streamlit",
    # Local inference
    "ollama", "llama-cpp-python", "ctransformers",
    # Training / fine-tuning
    "diffusers", "accelerate", "peft", "trl",
    # Structured generation
    "guidance", "dspy-ai", "instructor",
    # MCP (Model Context Protocol)
    "mcp",
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-node",
    "@modelcontextprotocol/server-deno",
    "mcp-python",
    "mcp-sdk",
}

# MCP-specific subset for targeted detection
MCP_PACKAGES: set[str] = {
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-node",
    "@modelcontextprotocol/server-deno",
    "mcp-python",
    "mcp-sdk",
    "mcp",
}


# ---------------------------------------------------------------------------
# Filesystem walking helpers
# ---------------------------------------------------------------------------

def walk_with_exclusions(
    root: str | Path,
    *,
    max_files: int = 0,
) -> list[str]:
    """Walk a directory tree, pruning excluded directories.

    Uses os.walk with topdown=True to skip entire subtrees, avoiding
    the performance issue of rglob traversing 50K+ files.

    Args:
        root: Root directory to walk.
        max_files: Stop after this many files (0 = unlimited).

    Returns:
        List of relative file paths (using forward slashes).
    """
    root_str = str(root)
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_str, topdown=True):
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDED_DIRS and not d.endswith(".egg-info")
        ]
        rel_dir = os.path.relpath(dirpath, root_str)
        for filename in filenames:
            if rel_dir == ".":
                files.append(filename)
            else:
                files.append(f"{rel_dir}/{filename}".replace("\\", "/"))
            if max_files and len(files) >= max_files:
                return files
    return files


def scan_directory_quick(entry: Path) -> dict[str, Any] | None:
    """Quick scan of a directory for target identification.

    Counts files and detects the presence of model files and source code.
    Caps traversal at 5000 files to stay fast.

    Args:
        entry: Directory to scan.

    Returns:
        Dict with name, path, file_count, has_models, has_code, or None
        if entry is not a directory.
    """
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
                if ext in CODE_EXTENSIONS:
                    has_code = True
                if file_count > 5000:
                    break
            if file_count > 5000:
                break
    except PermissionError:
        pass

    return {
        "name": entry.name,
        "path": str(entry),
        "file_count": file_count,
        "has_models": has_models,
        "has_code": has_code,
    }


def detect_ai_frameworks(root: Path) -> list[str]:
    """Detect AI frameworks by scanning dependency manifests.

    Checks requirements.txt, pyproject.toml, and package.json for
    known AI/ML framework packages.

    Args:
        root: Project root directory.

    Returns:
        List of detected framework names.
    """
    found: list[str] = []
    dep_files = [
        root / "requirements.txt",
        root / "pyproject.toml",
        root / "package.json",
    ]
    for dep_file in dep_files:
        if dep_file.is_file():
            try:
                text = dep_file.read_text(errors="ignore").lower()
                for fw in AI_FRAMEWORKS:
                    if fw.lower() in text and fw not in found:
                        found.append(fw)
            except Exception:
                pass
    return found
