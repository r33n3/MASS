"""File browser endpoints for scan target selection.

Provides a server-side directory browser so users can navigate
the container filesystem to select scan targets.

Also provides model file discovery using magic number detection
and code-level model usage scanning.
"""

import os
import re
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from mass.api.dependencies import CurrentTenantDep
from mass.analyzers.model_file.magic import identify_file, MagicSignature
from mass.core.filesystem import EXCLUDED_DIRS as _BROWSE_EXCLUDED_DIRS

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
    "/app/github_clones",
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
            if d in _BROWSE_EXCLUDED_DIRS:
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


# ── Model Usage Scanning ─────────────────────────────────────────────

# Patterns to detect model provider imports / usage in code
_PROVIDER_IMPORT_PATTERNS: dict[str, list[re.Pattern]] = {
    "OpenAI": [
        re.compile(r"(?:from\s+openai|import\s+openai|require\(['\"]openai['\"]|from\s+['\"]openai['\"])", re.I),
        re.compile(r"(?:ChatOpenAI|AzureOpenAI|OpenAI)\s*\(", re.I),
    ],
    "Anthropic": [
        re.compile(r"(?:from\s+anthropic|import\s+anthropic|require\(['\"]@anthropic|from\s+['\"]anthropic['\"])", re.I),
        re.compile(r"(?:ChatAnthropic|Anthropic)\s*\(", re.I),
    ],
    "Google / Gemini": [
        re.compile(r"(?:from\s+google\.generativeai|import\s+google\.generativeai|GenerativeModel|ChatGoogleGenerative)", re.I),
        re.compile(r"(?:from\s+['\"]@google/generative-ai['\"])", re.I),
    ],
    "Ollama": [
        re.compile(r"(?:from\s+ollama|import\s+ollama|ChatOllama|require\(['\"]ollama['\"])", re.I),
        re.compile(r"(?:OLLAMA_HOST|ollama\.chat|ollama\.generate)", re.I),
    ],
    "HuggingFace": [
        re.compile(r"(?:from\s+transformers|import\s+transformers|AutoModelFor|AutoTokenizer|pipeline\s*\()", re.I),
        re.compile(r"(?:from\s+huggingface_hub|HuggingFaceEndpoint)", re.I),
    ],
    "LangChain": [
        re.compile(r"(?:from\s+langchain|import\s+langchain|from\s+langgraph)", re.I),
        re.compile(r"(?:LLMChain|AgentExecutor|ConversationChain)", re.I),
    ],
    "AWS Bedrock": [
        re.compile(r"(?:bedrock-runtime|ChatBedrock|BedrockChat)", re.I),
    ],
    "Azure OpenAI": [
        re.compile(r"(?:AzureOpenAI|AZURE_OPENAI|azure\.openai)", re.I),
    ],
    "Cohere": [
        re.compile(r"(?:from\s+cohere|import\s+cohere|ChatCohere)", re.I),
    ],
    "Replicate": [
        re.compile(r"(?:from\s+replicate|import\s+replicate|REPLICATE_API)", re.I),
    ],
}

# Patterns for specific model name references in code/config
_MODEL_NAME_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    # (provider, model_family, pattern)
    ("OpenAI", "GPT-4o", re.compile(r"""['"]gpt-4o(?:-mini)?['"]""", re.I)),
    ("OpenAI", "GPT-4.1", re.compile(r"""['"]gpt-4\.1(?:-mini|-nano)?['"]""", re.I)),
    ("OpenAI", "GPT-5", re.compile(r"""['"]gpt-5(?:-nano|-mini)?['"]""", re.I)),
    ("OpenAI", "GPT-4", re.compile(r"""['"]gpt-4(?:-turbo)?['"]""", re.I)),
    ("OpenAI", "GPT-3.5", re.compile(r"""['"]gpt-3\.5-turbo['"]""", re.I)),
    ("OpenAI", "o-series", re.compile(r"""['"]o[134](?:-mini|-preview)?['"]""", re.I)),
    ("Anthropic", "Claude Opus", re.compile(r"""['"]claude-(?:opus|claude-opus)[\w.-]*['"]""", re.I)),
    ("Anthropic", "Claude Sonnet", re.compile(r"""['"]claude-(?:sonnet|claude-sonnet)[\w.-]*['"]""", re.I)),
    ("Anthropic", "Claude Haiku", re.compile(r"""['"]claude-(?:haiku|claude-haiku)[\w.-]*['"]""", re.I)),
    ("Anthropic", "Claude 3", re.compile(r"""['"]claude-3[\w.-]*['"]""", re.I)),
    ("Google", "Gemini", re.compile(r"""['"]gemini-[\d][\w.-]*['"]""", re.I)),
    ("Ollama", "Llama", re.compile(r"""['"](?:llama\d|llama-\d|llama[\d]*:)[\w.:.-]*['"]""", re.I)),
    ("Ollama", "Qwen", re.compile(r"""['"]qwen[\d][\w.:.-]*['"]""", re.I)),
    ("Ollama", "Mistral", re.compile(r"""['"]mistral(?:-\d|:)[\w.:.-]*['"]""", re.I)),
    ("Ollama", "Hermes", re.compile(r"""['"]hermes[\d][\w.:.-]*['"]""", re.I)),
    ("Ollama", "Phi", re.compile(r"""['"]phi-?[\d][\w.:.-]*['"]""", re.I)),
    ("Ollama", "CodeLlama", re.compile(r"""['"]codellama[\w.:.-]*['"]""", re.I)),
    ("HuggingFace", "HF Model", re.compile(r"""['"](?:TheBloke|meta-llama|mistralai|Qwen|google|microsoft|HuggingFaceH4|tiiuae|bigscience|EleutherAI)/[\w._-]+['"]""", re.I)),
    ("Cohere", "Command-R", re.compile(r"""['"]command-r[\w.-]*['"]""", re.I)),
]

# API key env var patterns
_API_KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI", re.compile(r"OPENAI[_-]?(?:API[_-]?)?KEY", re.I)),
    ("Anthropic", re.compile(r"ANTHROPIC[_-]?(?:API[_-]?)?KEY", re.I)),
    ("Google", re.compile(r"(?:GOOGLE|GEMINI)[_-]?(?:API[_-]?)?KEY", re.I)),
    ("Azure", re.compile(r"AZURE[_-]?(?:OPENAI[_-]?)?(?:API[_-]?)?KEY", re.I)),
    ("HuggingFace", re.compile(r"(?:HF|HUGGING[_-]?FACE)[_-]?(?:API[_-]?)?(?:KEY|TOKEN)", re.I)),
    ("Cohere", re.compile(r"COHERE[_-]?(?:API[_-]?)?KEY", re.I)),
    ("Replicate", re.compile(r"REPLICATE[_-]?(?:API[_-]?)?(?:KEY|TOKEN)", re.I)),
]

_CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".yaml", ".yml", ".json", ".toml", ".env", ".cfg", ".ini"}


class ModelUsageEntry(BaseModel):
    """A detected model provider/model reference in code."""
    provider: str = Field(description="Provider name (OpenAI, Anthropic, Ollama, etc.)")
    category: str = Field(description="Detection category: import, model_name, api_key, framework")
    detail: str = Field(description="What was found (model name, import, env var)")
    file: str = Field(description="File where detected")
    line: int | None = Field(default=None, description="Line number (if available)")


class ModelUsageResponse(BaseModel):
    """Response from code model usage scanning."""
    scan_path: str
    files_scanned: int
    providers: list[str] = Field(description="Unique providers detected")
    model_names: list[str] = Field(description="Specific model names referenced")
    local_model_files: int = Field(description="Count of local model files (GGUF, safetensors, etc.)")
    entries: list[ModelUsageEntry] = Field(description="All detected references")
    summary: dict[str, list[str]] = Field(description="Provider -> list of models/details")


@router.get(
    "/model-usage",
    response_model=ModelUsageResponse,
    summary="Discover model usage in code",
    description=(
        "Scan source code for model provider imports, specific model name references, "
        "API key environment variables, and framework usage. Shows what models "
        "the codebase can integrate with."
    ),
)
async def discover_model_usage(
    tenant: CurrentTenantDep,
    path: Annotated[str, Query(description="Directory to scan")] = "/app/targets",
    max_depth: Annotated[int, Query(ge=1, le=10, description="Max directory depth")] = 5,
    max_files: Annotated[int, Query(ge=1, le=5000, description="Max files to scan")] = 500,
) -> ModelUsageResponse:
    """Scan code files for model provider usage, model name references, and API key patterns."""
    try:
        abs_path = os.path.abspath(path)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid path")

    if not is_path_allowed(abs_path):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. Allowed paths: {', '.join(ALLOWED_ROOTS)}",
        )

    if not os.path.exists(abs_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Path not found: {path}")

    entries: list[ModelUsageEntry] = []
    files_scanned = 0
    local_model_count = 0
    seen: set[str] = set()  # Deduplicate entries

    for root, dirs, files in os.walk(abs_path):
        depth = root[len(abs_path):].count(os.sep)
        if depth >= max_depth:
            dirs.clear()
            continue

        dirs[:] = [d for d in dirs if d not in _BROWSE_EXCLUDED_DIRS and not d.startswith(".")]

        for filename in files:
            if files_scanned >= max_files:
                break

            file_path = os.path.join(root, filename)
            ext = os.path.splitext(filename)[1].lower()

            # Count local model files
            sig = identify_file(file_path)
            if sig and sig.is_model:
                local_model_count += 1

            # Only scan code files for model usage
            if ext not in _CODE_EXTENSIONS:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(64_000)  # Cap at 64KB per file
            except (OSError, PermissionError):
                continue

            files_scanned += 1
            rel_path = os.path.relpath(file_path, abs_path)

            # Scan for provider imports
            for provider, patterns in _PROVIDER_IMPORT_PATTERNS.items():
                for pat in patterns:
                    m = pat.search(content)
                    if m:
                        key = f"import:{provider}:{rel_path}"
                        if key not in seen:
                            seen.add(key)
                            # Find line number
                            line_no = content[:m.start()].count("\n") + 1
                            entries.append(ModelUsageEntry(
                                provider=provider,
                                category="import",
                                detail=m.group(0).strip(),
                                file=rel_path,
                                line=line_no,
                            ))
                        break  # One match per provider per file is enough

            # Scan for specific model names
            for provider, family, pat in _MODEL_NAME_PATTERNS:
                for m in pat.finditer(content):
                    model_str = m.group(0).strip("'\"")
                    # Skip HuggingFace org/model false positives (common path patterns)
                    if family == "HF Model" and ("/" not in model_str or model_str.count("/") > 1):
                        continue
                    key = f"model:{model_str}:{rel_path}"
                    if key not in seen:
                        seen.add(key)
                        line_no = content[:m.start()].count("\n") + 1
                        entries.append(ModelUsageEntry(
                            provider=provider,
                            category="model_name",
                            detail=model_str,
                            file=rel_path,
                            line=line_no,
                        ))

            # Scan for API key env vars
            for provider, pat in _API_KEY_PATTERNS:
                m = pat.search(content)
                if m:
                    key = f"apikey:{provider}:{rel_path}"
                    if key not in seen:
                        seen.add(key)
                        line_no = content[:m.start()].count("\n") + 1
                        entries.append(ModelUsageEntry(
                            provider=provider,
                            category="api_key",
                            detail=m.group(0),
                            file=rel_path,
                            line=line_no,
                        ))

        if files_scanned >= max_files:
            break

    # Build summary: provider -> unique details
    providers_set: set[str] = set()
    model_names_set: set[str] = set()
    summary: dict[str, list[str]] = {}

    for e in entries:
        providers_set.add(e.provider)
        if e.category == "model_name":
            model_names_set.add(e.detail)

        if e.provider not in summary:
            summary[e.provider] = []
        detail_str = f"{e.detail} ({e.category})"
        if detail_str not in summary[e.provider]:
            summary[e.provider].append(detail_str)

    return ModelUsageResponse(
        scan_path=abs_path,
        files_scanned=files_scanned,
        providers=sorted(providers_set),
        model_names=sorted(model_names_set),
        local_model_files=local_model_count,
        entries=entries,
        summary=summary,
    )


# ── File Content (code context for findings) ──


class FileContentResponse(BaseModel):
    """Response from reading file content around a specific line."""
    path: str
    line_number: int
    context_before: int
    context_after: int
    start_line: int
    end_line: int
    total_lines: int
    lines: list[dict] = Field(description="List of {line_number, content} dicts")
    language: str = Field(default="", description="Detected language hint")


# Map file extensions to language hints for syntax highlighting
_LANG_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "jsx", ".tsx": "tsx", ".java": "java", ".go": "go",
    ".rs": "rust", ".rb": "ruby", ".php": "php", ".c": "c",
    ".cpp": "cpp", ".h": "c", ".hpp": "cpp", ".cs": "csharp",
    ".swift": "swift", ".kt": "kotlin", ".scala": "scala",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json",
    ".toml": "toml", ".ini": "ini", ".xml": "xml", ".html": "html",
    ".css": "css", ".scss": "scss", ".sh": "bash", ".bash": "bash",
    ".sql": "sql", ".md": "markdown", ".dockerfile": "dockerfile",
}

# Max file size we'll read (5 MB)
_MAX_FILE_SIZE = 5 * 1024 * 1024


@router.get(
    "/file-content",
    response_model=FileContentResponse,
    summary="Read file content around a specific line",
    description=(
        "Returns lines from a source file centered around a specified line number. "
        "Used for displaying code context in finding details."
    ),
)
async def read_file_content(
    tenant: CurrentTenantDep,
    path: Annotated[str, Query(description="Absolute file path")],
    line: Annotated[int, Query(ge=1, description="Target line number")] = 1,
    context: Annotated[int, Query(ge=0, le=50, description="Lines of context before and after")] = 5,
) -> FileContentResponse:
    """Read file content around a specific line for code context display."""
    abs_path = os.path.abspath(path)

    if not is_path_allowed(abs_path):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. File must be within allowed paths.",
        )

    if not os.path.isfile(abs_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found: {path}",
        )

    file_size = os.path.getsize(abs_path)
    if file_size > _MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large ({file_size} bytes). Max: {_MAX_FILE_SIZE}.",
        )

    # Detect language from extension
    ext = Path(abs_path).suffix.lower()
    language = _LANG_MAP.get(ext, "")

    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read file: {e}",
        )

    total_lines = len(all_lines)
    target_idx = min(line - 1, total_lines - 1)  # 0-based
    start_idx = max(0, target_idx - context)
    end_idx = min(total_lines, target_idx + context + 1)

    lines = []
    for i in range(start_idx, end_idx):
        lines.append({
            "line_number": i + 1,
            "content": all_lines[i].rstrip("\n\r"),
        })

    return FileContentResponse(
        path=abs_path,
        line_number=line,
        context_before=context,
        context_after=context,
        start_line=start_idx + 1,
        end_line=end_idx,
        total_lines=total_lines,
        lines=lines,
        language=language,
    )
