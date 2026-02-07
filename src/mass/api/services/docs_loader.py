"""Documentation loader service.

Reads markdown files from the docs/ directory and provides searchable
snippets for injection into the chat system prompt, plus structured
responses for the docs API endpoint.
"""

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Root docs directory – resolve from project root, not relative to this file.
# In Docker: /app/docs   Locally: <repo>/docs
# Walk up from src/mass/api/services/docs_loader.py -> 4 parents to reach project root.
_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_DOCS_ROOT = _PROJECT_ROOT / "docs"

# In-memory cache: loaded once per process
_docs_cache: list[dict[str, Any]] | None = None


def _parse_markdown_sections(filepath: Path) -> list[dict[str, Any]]:
    """Split a markdown file into sections by headings."""
    text = filepath.read_text(encoding="utf-8", errors="replace")
    relative = filepath.relative_to(_DOCS_ROOT)
    category = relative.parts[0] if len(relative.parts) > 1 else "general"

    sections: list[dict[str, Any]] = []
    current_title = filepath.stem.replace("-", " ").replace("_", " ").title()
    current_body: list[str] = []

    for line in text.splitlines():
        heading_match = re.match(r"^(#{1,3})\s+(.+)", line)
        if heading_match:
            # Save previous section
            if current_body:
                body_text = "\n".join(current_body).strip()
                if body_text:
                    sections.append({
                        "title": current_title,
                        "body": body_text,
                        "file": str(relative),
                        "category": category,
                    })
            current_title = heading_match.group(2).strip()
            current_body = []
        else:
            current_body.append(line)

    # Last section
    if current_body:
        body_text = "\n".join(current_body).strip()
        if body_text:
            sections.append({
                "title": current_title,
                "body": body_text,
                "file": str(relative),
                "category": category,
            })

    return sections


def _load_all_docs() -> list[dict[str, Any]]:
    """Walk the docs directory and parse all markdown files."""
    global _docs_cache
    if _docs_cache is not None:
        return _docs_cache

    sections: list[dict[str, Any]] = []

    if not _DOCS_ROOT.is_dir():
        logger.warning("Docs directory not found at %s", _DOCS_ROOT)
        _docs_cache = sections
        return sections

    for md_file in sorted(_DOCS_ROOT.rglob("*.md")):
        try:
            sections.extend(_parse_markdown_sections(md_file))
        except Exception as exc:
            logger.debug("Failed to parse %s: %s", md_file, exc)

    logger.info("Loaded %d documentation sections from %s", len(sections), _DOCS_ROOT)
    _docs_cache = sections
    return sections


def reload_docs() -> int:
    """Force-reload all documentation files. Returns section count."""
    global _docs_cache
    _docs_cache = None
    return len(_load_all_docs())


def search_docs(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """Search documentation sections by keyword relevance.

    Returns the top *limit* matching sections sorted by relevance score.
    """
    all_sections = _load_all_docs()
    if not all_sections or not query.strip():
        return []

    query_lower = query.lower()
    keywords = [w for w in re.split(r"\W+", query_lower) if len(w) > 2]

    scored: list[tuple[float, dict[str, Any]]] = []
    for section in all_sections:
        title_lower = section["title"].lower()
        body_lower = section["body"].lower()

        score = 0.0
        for kw in keywords:
            if kw in title_lower:
                score += 3.0
            if kw in body_lower:
                score += 1.0 + body_lower.count(kw) * 0.2

        if score > 0:
            scored.append((score, section))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [s[1] for s in scored[:limit]]


def get_docs_for_chat(message: str) -> str:
    """Return a compact documentation context string for the chat system prompt."""
    matches = search_docs(message, limit=3)
    if not matches:
        return ""

    lines = ["\n--- DOCUMENTATION CONTEXT ---"]
    for m in matches:
        # Truncate body to keep context compact
        body = m["body"][:400]
        if len(m["body"]) > 400:
            body += "..."
        lines.append(f"[{m['category']}/{m['title']}]\n{body}\n")
    lines.append("--- END DOCUMENTATION ---")
    return "\n".join(lines)


def list_all_docs() -> list[dict[str, Any]]:
    """Return all documentation sections (for the docs API endpoint)."""
    return _load_all_docs()


def list_categories() -> list[str]:
    """Return unique documentation categories."""
    return sorted({s["category"] for s in _load_all_docs()})
