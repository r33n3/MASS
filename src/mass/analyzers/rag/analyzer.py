"""RAG pipeline security analyzer.

Scans source code for insecure patterns in vector database usage,
embedding pipelines, document ingestion, and retrieval code.
Pattern-based analysis matching the existing analyzer conventions.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mass.core.types import Severity

from .patterns import (
    RAG_IMPORT_PATTERNS,
    RAG_INDICATOR_PATTERNS,
    RAG_PATTERNS,
    RAGPattern,
    RAGRiskCategory,
)

logger = logging.getLogger(__name__)


@dataclass
class RAGFinding:
    """A finding from the RAG pipeline analyzer."""

    pattern_id: str
    category: RAGRiskCategory
    title: str
    description: str
    severity: Severity
    file_path: str
    line_number: int | None = None
    code_snippet: str | None = None
    remediation: str = ""
    matched_pattern: str = ""


@dataclass
class RAGAnalysisResult:
    """Result of RAG pipeline analysis on a file or directory."""

    findings: list[RAGFinding] = field(default_factory=list)
    files_analyzed: int = 0
    rag_components_found: int = 0
    errors: list[str] = field(default_factory=list)


class RAGAnalyzer:
    """Analyzes source code for RAG pipeline security issues.

    Scans for:
    - Unvalidated document ingestion
    - Unauthenticated vector DB access
    - Missing chunk-level access control
    - Hardcoded connection strings
    - Missing relevance filtering
    - Unsanitized retrieval output
    - Unsigned embedding models
    - Insecure chunking configuration
    """

    def __init__(self) -> None:
        self._compiled_patterns: list[tuple[RAGPattern, list[re.Pattern]]] = []
        self._import_patterns: list[re.Pattern] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for pattern in RAG_PATTERNS:
            compiled = []
            for regex in pattern.code_patterns:
                try:
                    compiled.append(re.compile(regex))
                except re.error:
                    logger.warning("Invalid regex in pattern %s: %s", pattern.id, regex)
            self._compiled_patterns.append((pattern, compiled))

        for regex in RAG_IMPORT_PATTERNS:
            try:
                self._import_patterns.append(re.compile(regex))
            except re.error:
                pass

    def analyze_file(self, file_path: Path | str) -> RAGAnalysisResult:
        """Analyze a single file for RAG security issues."""
        result = RAGAnalysisResult()
        file_path = Path(file_path)

        if not file_path.is_file():
            return result

        # Skip large files
        try:
            if file_path.stat().st_size > 2 * 1024 * 1024:
                return result
        except OSError:
            return result

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            result.errors.append(f"Failed to read {file_path}: {e}")
            return result

        result.files_analyzed = 1
        lines = content.split("\n")

        # Check if file contains RAG-related imports
        has_rag_imports = any(p.search(content) for p in self._import_patterns)
        if has_rag_imports:
            result.rag_components_found = 1

        # Scan for patterns
        for pattern, compiled_regexes in self._compiled_patterns:
            for regex in compiled_regexes:
                for i, line in enumerate(lines, 1):
                    match = regex.search(line)
                    if match:
                        # Extract snippet (3 lines context)
                        start = max(0, i - 3)
                        end = min(len(lines), i + 2)
                        snippet = "\n".join(
                            f"{'>>>' if j == i else '   '} {j:4d} | {lines[j-1]}"
                            for j in range(start + 1, end + 1)
                        )

                        finding = RAGFinding(
                            pattern_id=pattern.id,
                            category=pattern.category,
                            title=pattern.title,
                            description=pattern.description,
                            severity=pattern.severity,
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=snippet,
                            remediation=pattern.remediation,
                            matched_pattern=match.group(0),
                        )
                        result.findings.append(finding)
                        break  # One match per regex per file is enough

        return result

    def analyze_directory(self, path: Path | str) -> RAGAnalysisResult:
        """Analyze a directory for RAG pipeline security issues."""
        result = RAGAnalysisResult()
        path = Path(path)

        if not path.is_dir():
            return result

        # Find relevant files
        python_files = list(path.rglob("*.py"))
        for py_file in python_files:
            try:
                file_result = self.analyze_file(py_file)
                result.findings.extend(file_result.findings)
                result.files_analyzed += file_result.files_analyzed
                result.rag_components_found += file_result.rag_components_found
                result.errors.extend(file_result.errors)
            except Exception as e:
                result.errors.append(f"Failed to analyze {py_file}: {e}")

        return result
