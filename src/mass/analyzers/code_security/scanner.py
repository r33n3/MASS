"""Phase A: Static regex scanner for code security vulnerabilities.

Walks all code files, applies security patterns, extracts context for
LLM verification, and deduplicates candidates by (file, line).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mass.core.types import Severity

from mass.analyzers.code_security.patterns import (
    LANGUAGE_EXTENSIONS,
    SECURITY_PATTERNS,
    SecurityCategory,
    SecurityPattern,
)

logger = logging.getLogger(__name__)

# Reuse skip lists from secrets detector for consistency
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".db", ".sqlite", ".sqlite3",
}

SKIP_DIRECTORIES = {
    ".git", ".svn", ".hg",
    "__pycache__", ".pytest_cache", ".mypy_cache",
    "node_modules", ".npm",
    "venv", ".venv", "env", ".env",
    ".tox", ".nox",
    "dist", "build", "target",
    "coverage", ".coverage",
    ".eggs",
    # Vendored/bundled Python installations and site-packages
    "site-packages", "Lib", "lib", "Scripts", "Include",
    # Common vendored dependency directories
    "vendor", "vendors", "third_party", "third-party",
    "external", "deps",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    "Pipfile.lock", "requirements-lock.txt",
}

MAX_FILE_SIZE = 200 * 1024  # 200KB

# Severity ranking for dedup (higher = more severe)
_SEV_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class SecurityCandidate:
    """A candidate vulnerability found by static scanning."""

    rule_id: str
    pattern_name: str
    category: SecurityCategory
    severity: Severity
    description: str
    file_path: str
    line_number: int
    matched_line: str
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    file_role: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)
    remediation_hint: str = ""
    requires_llm_verification: bool = True


class CodeSecurityScanner:
    """Phase A: Fast static regex scanning for security vulnerabilities."""

    def __init__(
        self,
        patterns: list[SecurityPattern] | None = None,
        architecture_map: dict[str, Any] | None = None,
    ) -> None:
        self._patterns = patterns or SECURITY_PATTERNS
        self._architecture_map = architecture_map or {}
        self._file_roles: dict[str, str] = self._build_file_roles()

    def _build_file_roles(self) -> dict[str, str]:
        """Map file paths to architectural roles from the architecture map."""
        roles: dict[str, str] = {}
        arch = self._architecture_map

        for ep in arch.get("entry_points", []):
            loc = ep.get("location", "")
            fpath = loc.split(":")[0] if ":" in loc else loc
            if fpath:
                roles[fpath] = "entry_point"

        for mc in arch.get("model_connections", []):
            loc = mc.get("call_location", "")
            fpath = loc.split(":")[0] if ":" in loc else loc
            if fpath:
                roles[fpath] = "model_connection"

        for td in arch.get("tool_definitions", []):
            loc = td.get("location", "")
            fpath = loc.split(":")[0] if ":" in loc else loc
            if fpath:
                roles[fpath] = "tool_definition"

        return roles

    def scan_directory(self, directory: Path) -> list[SecurityCandidate]:
        """Scan all code files in a directory for security vulnerabilities.

        Args:
            directory: Root directory to scan.

        Returns:
            Deduplicated list of security candidates.
        """
        candidates: list[SecurityCandidate] = []

        for file_path in self._iter_files(directory):
            try:
                file_candidates = self.scan_file(file_path, relative_to=directory)
                candidates.extend(file_candidates)
            except Exception as e:
                logger.warning("Error scanning %s: %s", file_path, e)

        return self._deduplicate(candidates)

    def scan_file(
        self, file_path: Path, relative_to: Path | None = None
    ) -> list[SecurityCandidate]:
        """Scan a single file for security vulnerabilities.

        Args:
            file_path: Absolute path to the file.
            relative_to: Base directory for relative path computation.

        Returns:
            List of security candidates found in this file.
        """
        rel_path = str(
            file_path.relative_to(relative_to) if relative_to else file_path
        ).replace("\\", "/")

        ext = file_path.suffix.lower()
        applicable_patterns = self._get_patterns_for_extension(ext)
        if not applicable_patterns:
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as e:
            logger.debug("Cannot read %s: %s", file_path, e)
            return []

        lines = content.splitlines()
        candidates: list[SecurityCandidate] = []

        for pattern in applicable_patterns:
            for line_idx, line in enumerate(lines):
                if pattern.pattern.search(line):
                    # Check false positive patterns
                    if self._is_false_positive(line, pattern):
                        continue

                    ctx_n = pattern.context_lines
                    context_before = lines[max(0, line_idx - ctx_n):line_idx]
                    context_after = lines[line_idx + 1:line_idx + 1 + ctx_n]

                    # Check false positive patterns in surrounding context
                    full_context = "\n".join(context_before + [line] + context_after)
                    if self._is_context_false_positive(full_context, pattern):
                        continue

                    file_role = self._file_roles.get(rel_path)

                    candidates.append(SecurityCandidate(
                        rule_id=pattern.rule_id,
                        pattern_name=pattern.name,
                        category=pattern.category,
                        severity=pattern.severity,
                        description=pattern.description,
                        file_path=rel_path,
                        line_number=line_idx + 1,
                        matched_line=line.rstrip(),
                        context_before=context_before,
                        context_after=context_after,
                        file_role=file_role,
                        cwe_ids=list(pattern.cwe_ids),
                        owasp_ids=list(pattern.owasp_ids),
                        remediation_hint=pattern.remediation_hint,
                        requires_llm_verification=pattern.requires_llm_verification,
                    ))

        return candidates

    def _get_patterns_for_extension(self, ext: str) -> list[SecurityPattern]:
        """Get patterns applicable to a file extension."""
        applicable = []
        for pattern in self._patterns:
            for lang in pattern.languages:
                if ext in LANGUAGE_EXTENSIONS.get(lang, set()):
                    applicable.append(pattern)
                    break
        return applicable

    @staticmethod
    def _is_false_positive(line: str, pattern: SecurityPattern) -> bool:
        """Check if the matched line is a false positive."""
        for fp_pattern in pattern.false_positive_patterns:
            if fp_pattern.search(line):
                return True
        return False

    @staticmethod
    def _is_context_false_positive(context: str, pattern: SecurityPattern) -> bool:
        """Check surrounding context for false positive indicators.

        For CS-051 (no_auth_dependency), check if Depends() appears
        in the function signature context.
        """
        if pattern.rule_id == "CS-051":
            for fp in pattern.false_positive_patterns:
                if fp.search(context):
                    return True
        return False

    @staticmethod
    def _deduplicate(candidates: list[SecurityCandidate]) -> list[SecurityCandidate]:
        """Deduplicate candidates by (file_path, line_number), keeping highest severity."""
        best: dict[tuple[str, int], SecurityCandidate] = {}

        for c in candidates:
            key = (c.file_path, c.line_number)
            existing = best.get(key)
            if existing is None:
                best[key] = c
            elif _SEV_ORDER.get(c.severity, 0) > _SEV_ORDER.get(existing.severity, 0):
                best[key] = c

        return list(best.values())

    def _iter_files(self, directory: Path) -> list[Path]:
        """Walk directory and yield scannable files."""
        files: list[Path] = []
        try:
            self._walk(directory, files)
        except Exception as e:
            logger.warning("Error walking directory %s: %s", directory, e)
        return files

    def _walk(self, directory: Path, out: list[Path]) -> None:
        """Recursively walk directory collecting code files."""
        try:
            entries = sorted(directory.iterdir())
        except (PermissionError, OSError):
            return

        for entry in entries:
            name = entry.name

            if entry.is_dir():
                if name in SKIP_DIRECTORIES:
                    continue
                if name.endswith(".egg-info") or name.endswith(".dist-info"):
                    continue
                # Skip directories that look like bundled Python runtimes
                if name.startswith("python") or name.startswith("Python"):
                    continue
                self._walk(entry, out)
            elif entry.is_file():
                if name in SKIP_FILES:
                    continue
                ext = entry.suffix.lower()
                if ext in SKIP_EXTENSIONS:
                    continue
                # Only scan files that have applicable patterns
                has_patterns = any(
                    ext in LANGUAGE_EXTENSIONS.get(lang, set())
                    for p in self._patterns
                    for lang in p.languages
                )
                if not has_patterns:
                    continue
                try:
                    if entry.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                out.append(entry)
