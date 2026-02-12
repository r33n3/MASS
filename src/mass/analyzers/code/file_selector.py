"""Static file selection for AI architecture analysis.

Quickly identifies the most important files in a codebase for LLM analysis
by scoring them based on heuristics: entry points, AI SDK imports, tool
definitions, prompt content, and config files.
"""

from __future__ import annotations

import ast
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from mass.core.filesystem import AI_FRAMEWORKS, EXCLUDED_DIRS

logger = logging.getLogger(__name__)

# Maximum file size to read for scoring (100 KB)
_MAX_READ_SIZE = 100_000
# Maximum content to include per file for LLM analysis (3000 chars ≈ 750 tokens)
_MAX_CONTENT_CHARS = 3000

# ── Scoring patterns ────────────────────────────────────────────────

ENTRY_POINT_NAMES = {
    "main.py", "app.py", "__main__.py", "server.py", "cli.py", "run.py",
    "index.js", "index.ts", "server.js", "server.ts", "app.js", "app.ts",
    "main.js", "main.ts",
}

_AI_IMPORT_PATTERNS = re.compile(
    r"\b(?:openai|anthropic|langchain|langgraph|crewai|autogen|"
    r"llama_index|llamaindex|transformers|ollama|"
    r"gradio|streamlit|chromadb|mcp)\b",
    re.IGNORECASE,
)

_TOOL_PATTERNS = re.compile(
    r"(?:@tool\b|Tool\s*\(|tools\s*=\s*\[|function_call|"
    r"tool_choice|mcp\.server\.tool|register_tool|add_tool)",
    re.IGNORECASE,
)

_PROMPT_PATTERNS = re.compile(
    r"(?:system_prompt|system_message|SYSTEM|SystemMessage\(|"
    r"ChatPromptTemplate|PromptTemplate|instruction|"
    r"\.system\s*=|role.*system)",
    re.IGNORECASE,
)

_MODEL_CALL_PATTERNS = re.compile(
    r"(?:\.chat\.completions\.create|\.messages\.create|"
    r"\.generate\(|\.invoke\(|\.run\(|\.complete\(|"
    r"ChatOpenAI|ChatAnthropic|OllamaLLM|Ollama\(|"
    r"OpenAI\(|Anthropic\()",
)

_CONFIG_MODEL_PATTERNS = re.compile(
    r"(?:model|endpoint|api_key|api_base|base_url|"
    r"openai|anthropic|ollama|temperature|max_tokens)",
    re.IGNORECASE,
)

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".ini", ".env"}


@dataclass
class ScoredFile:
    """A file scored for relevance to AI architecture analysis."""

    path: Path
    relative_path: str
    score: int = 0
    signals: list[str] = field(default_factory=list)
    content: str = ""  # truncated content for LLM
    language: str = ""

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "relative_path": self.relative_path,
            "score": self.score,
            "signals": self.signals,
            "language": self.language,
        }


def _detect_language(path: Path) -> str:
    """Detect programming language from file extension."""
    ext = path.suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".toml": "toml",
    }.get(ext, "text")


def _extract_python_imports(source: str) -> set[str]:
    """Extract top-level import module names from Python source using AST."""
    imports: set[str] = set()
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
    except SyntaxError:
        pass
    return imports


def _score_file(path: Path, root: Path) -> ScoredFile | None:
    """Score a single file for AI architecture relevance."""
    ext = path.suffix.lower()
    is_code = ext in CODE_EXTENSIONS
    is_config = ext in CONFIG_EXTENSIONS

    if not is_code and not is_config:
        return None

    rel = str(path.relative_to(root)).replace("\\", "/")
    sf = ScoredFile(path=path, relative_path=rel, language=_detect_language(path))

    # Read file content (capped)
    try:
        raw = path.read_text(errors="ignore")[:_MAX_READ_SIZE]
    except Exception:
        return None

    if not raw.strip():
        return None

    name = path.name.lower()

    # ── Entry point detection ──
    if name in {n.lower() for n in ENTRY_POINT_NAMES}:
        sf.score += 100
        sf.signals.append("entry_point")

    if is_code:
        # ── AI SDK imports ──
        if ext == ".py":
            imports = _extract_python_imports(raw)
            ai_imports = imports & {fw.replace("-", "_") for fw in AI_FRAMEWORKS}
            if ai_imports:
                sf.score += 50
                sf.signals.append(f"ai_imports:{','.join(sorted(ai_imports))}")
        else:
            # JS/TS: check first 80 lines for import/require
            head = "\n".join(raw.split("\n")[:80])
            if _AI_IMPORT_PATTERNS.search(head):
                sf.score += 50
                sf.signals.append("ai_imports")

        # ── Model API calls ──
        if _MODEL_CALL_PATTERNS.search(raw):
            sf.score += 40
            sf.signals.append("model_calls")

        # ── Tool definitions ──
        if _TOOL_PATTERNS.search(raw):
            sf.score += 40
            sf.signals.append("tool_definitions")

        # ── System prompts / instructions ──
        if _PROMPT_PATTERNS.search(raw):
            sf.score += 30
            sf.signals.append("prompt_content")

    elif is_config:
        # ── Config files referencing models/endpoints ──
        if _CONFIG_MODEL_PATTERNS.search(raw):
            sf.score += 20
            sf.signals.append("config_model_refs")

    # Only keep files with at least one signal
    if sf.score == 0:
        return None

    # Store truncated content for LLM analysis
    sf.content = raw[:_MAX_CONTENT_CHARS]
    return sf


def select_files(
    root: Path,
    max_files: int = 30,
) -> list[ScoredFile]:
    """Select the most relevant files for AI architecture analysis.

    Args:
        root: Root directory to scan.
        max_files: Maximum number of files to return.

    Returns:
        List of ScoredFile sorted by score descending.
    """
    if not root.is_dir():
        return []

    scored: list[ScoredFile] = []
    total_files = 0

    excluded_lower = {d.lower() for d in EXCLUDED_DIRS}

    for dirpath_str, dirnames, filenames in os.walk(root):
        # Prune excluded directories in-place
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in excluded_lower and not d.startswith(".")
        ]

        dirpath = Path(dirpath_str)
        for fname in filenames:
            total_files += 1
            fpath = dirpath / fname

            # Skip large files
            try:
                if fpath.stat().st_size > _MAX_READ_SIZE:
                    continue
            except OSError:
                continue

            sf = _score_file(fpath, root)
            if sf:
                scored.append(sf)

    # Sort by score descending, take top N
    scored.sort(key=lambda f: f.score, reverse=True)
    result = scored[:max_files]

    logger.info(
        "File selection: %d/%d files scored, %d selected (top score: %d)",
        len(scored), total_files, len(result),
        result[0].score if result else 0,
    )

    return result
