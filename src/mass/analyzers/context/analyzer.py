"""Context file analyzer.

Analyzes AI context files for security risks and policy violations.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from mass.core.types import Severity
from mass.analyzers.context.patterns import (
    RiskPattern,
    RiskCategory,
    RISK_PATTERNS,
)

logger = logging.getLogger(__name__)


class ContextFileType(str, Enum):
    """Types of context files."""
    CLAUDE_MD = "claude_md"
    CURSOR_RULES = "cursor_rules"
    SYSTEM_PROMPT = "system_prompt"
    INSTRUCTIONS = "instructions"
    RULES = "rules"
    CONFIG = "config"
    UNKNOWN = "unknown"


# File patterns for context file detection
CONTEXT_FILE_PATTERNS = {
    ContextFileType.CLAUDE_MD: [
        r"CLAUDE\.md$",
        r"\.claude/.*\.md$",
    ],
    ContextFileType.CURSOR_RULES: [
        r"\.cursorrules$",
        r"\.cursor/rules$",
    ],
    ContextFileType.SYSTEM_PROMPT: [
        r"system[_-]?prompt\.(txt|md)$",
        r"prompt\.(txt|md)$",
    ],
    ContextFileType.INSTRUCTIONS: [
        r"instructions?\.(txt|md)$",
        r"INSTRUCTIONS?\.md$",
    ],
    ContextFileType.RULES: [
        r"rules\.(txt|md|yaml|json)$",
        r"RULES\.md$",
    ],
}


@dataclass
class ContextFinding:
    """A security finding in a context file."""
    pattern_name: str
    category: RiskCategory
    severity: Severity
    title: str
    description: str
    file_path: Path
    line_number: int | None = None
    line_content: str | None = None
    match_text: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pattern_name": self.pattern_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "line_content": self.line_content,
            "match_text": self.match_text,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ContextAnalysisResult:
    """Result of context file analysis."""
    file_path: Path
    file_type: ContextFileType
    findings: list[ContextFinding] = field(default_factory=list)
    lines_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        """Check if no security issues were found."""
        return len(self.findings) == 0

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def findings_by_category(self, category: RiskCategory) -> list[ContextFinding]:
        """Get findings filtered by category."""
        return [f for f in self.findings if f.category == category]


class ContextAnalyzer:
    """Analyzes AI context files for security risks.

    Scans files like CLAUDE.md, .cursorrules, system prompts for:
    - Jailbreak attempts
    - Prompt injection
    - Data exfiltration instructions
    - Unsafe execution patterns
    - Policy violations
    """

    def __init__(
        self,
        patterns: list[RiskPattern] | None = None,
        min_severity: Severity = Severity.LOW,
        custom_patterns: list[RiskPattern] | None = None,
    ):
        """Initialize context analyzer.

        Args:
            patterns: Risk patterns to use. Defaults to all patterns.
            min_severity: Minimum severity to report.
            custom_patterns: Additional custom patterns.
        """
        self.patterns = patterns or RISK_PATTERNS.copy()
        self.min_severity = min_severity

        if custom_patterns:
            self.patterns.extend(custom_patterns)

        # Severity ordering for filtering
        self._severity_order = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3,
        }

    def detect_file_type(self, file_path: Path) -> ContextFileType:
        """Detect the type of context file.

        Args:
            file_path: Path to the file.

        Returns:
            Detected file type.
        """
        path_str = str(file_path)

        for file_type, patterns in CONTEXT_FILE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, path_str, re.IGNORECASE):
                    return file_type

        return ContextFileType.UNKNOWN

    def analyze_file(self, file_path: Path | str) -> ContextAnalysisResult:
        """Analyze a context file for security risks.

        Args:
            file_path: Path to the context file.

        Returns:
            Analysis result with findings.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return ContextAnalysisResult(
                file_path=file_path,
                file_type=ContextFileType.UNKNOWN,
                errors=[f"File not found: {file_path}"],
            )

        file_type = self.detect_file_type(file_path)

        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = file_path.read_text(encoding="latin-1")
            except Exception as e:
                return ContextAnalysisResult(
                    file_path=file_path,
                    file_type=file_type,
                    errors=[f"Could not read file: {e}"],
                )
        except Exception as e:
            return ContextAnalysisResult(
                file_path=file_path,
                file_type=file_type,
                errors=[f"Error reading file: {e}"],
            )

        return self.analyze_content(content, file_path, file_type)

    def analyze_content(
        self,
        content: str,
        file_path: Path | None = None,
        file_type: ContextFileType = ContextFileType.UNKNOWN,
    ) -> ContextAnalysisResult:
        """Analyze content for security risks.

        Args:
            content: Content to analyze.
            file_path: Optional file path for context.
            file_type: Type of context file.

        Returns:
            Analysis result with findings.
        """
        file_path = file_path or Path("<string>")
        lines = content.splitlines()

        result = ContextAnalysisResult(
            file_path=file_path,
            file_type=file_type,
            lines_scanned=len(lines),
        )

        # Track unique findings to avoid duplicates
        seen_findings: set[tuple[str, int]] = set()

        for pattern in self.patterns:
            # Skip patterns below minimum severity
            if self._severity_order.get(pattern.severity, 0) < self._severity_order.get(self.min_severity, 0):
                continue

            for finding in self._find_pattern_matches(
                content, pattern, lines, file_path
            ):
                # Deduplicate
                key = (pattern.name, finding.line_number or 0)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(finding)

        return result

    def _find_pattern_matches(
        self,
        content: str,
        pattern: RiskPattern,
        lines: list[str],
        file_path: Path,
    ) -> Iterator[ContextFinding]:
        """Find matches for a pattern.

        Args:
            content: Content to search.
            pattern: Pattern to match.
            lines: Content split into lines.
            file_path: File path for context.

        Yields:
            Context findings.
        """
        compiled = pattern.compiled_pattern

        for match in compiled.finditer(content):
            # Find line number
            line_num = content[:match.start()].count("\n") + 1
            line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else ""

            # Check for false positives
            if self._is_false_positive(match.group(0), pattern, line_content):
                continue

            yield ContextFinding(
                pattern_name=pattern.name,
                category=pattern.category,
                severity=pattern.severity,
                title=f"{pattern.category.value.replace('_', ' ').title()}: {pattern.name}",
                description=pattern.description,
                file_path=file_path,
                line_number=line_num,
                line_content=line_content.strip(),
                match_text=match.group(0),
                remediation=pattern.remediation,
            )

    def _is_false_positive(
        self,
        match_text: str,
        pattern: RiskPattern,
        line_content: str,
    ) -> bool:
        """Check if match is a false positive.

        Args:
            match_text: Matched text.
            pattern: Pattern that matched.
            line_content: Full line content.

        Returns:
            True if likely a false positive.
        """
        # Check pattern-specific hints
        for hint in pattern.false_positive_hints:
            if hint.lower() in line_content.lower():
                return True

        # Common false positive indicators
        false_positive_contexts = [
            "example of what not to do",
            "don't do this",
            "avoid doing",
            "never do",
            "bad example",
            "anti-pattern",
            "prohibited example",
        ]

        line_lower = line_content.lower()
        for fp_context in false_positive_contexts:
            if fp_context in line_lower:
                return True

        return False

    def analyze_directory(
        self,
        directory: Path | str,
        recursive: bool = True,
    ) -> list[ContextAnalysisResult]:
        """Analyze all context files in a directory.

        Args:
            directory: Directory to scan.
            recursive: Scan subdirectories.

        Returns:
            List of analysis results.
        """
        directory = Path(directory)
        results = []

        pattern = "**/*" if recursive else "*"
        for file_path in directory.glob(pattern):
            if file_path.is_file() and self._is_context_file(file_path):
                result = self.analyze_file(file_path)
                results.append(result)

        return results

    def _is_context_file(self, file_path: Path) -> bool:
        """Check if file is a context file.

        Args:
            file_path: Path to check.

        Returns:
            True if file is a context file.
        """
        # Check known patterns
        if self.detect_file_type(file_path) != ContextFileType.UNKNOWN:
            return True

        # Check common extensions and names
        name_lower = file_path.name.lower()
        if name_lower.endswith((".md", ".txt")):
            keywords = ["prompt", "rule", "instruction", "system", "context", "claude"]
            return any(kw in name_lower for kw in keywords)

        return False

    def get_summary(self, results: list[ContextAnalysisResult]) -> dict[str, Any]:
        """Get summary of multiple analysis results.

        Args:
            results: List of analysis results.

        Returns:
            Summary dictionary.
        """
        total_findings = sum(len(r.findings) for r in results)
        total_critical = sum(r.critical_count for r in results)
        total_high = sum(r.high_count for r in results)

        by_category: dict[str, int] = {}
        for result in results:
            for finding in result.findings:
                cat = finding.category.value
                by_category[cat] = by_category.get(cat, 0) + 1

        return {
            "files_scanned": len(results),
            "total_findings": total_findings,
            "critical_count": total_critical,
            "high_count": total_high,
            "by_category": by_category,
            "files_with_issues": [
                str(r.file_path) for r in results if not r.is_safe
            ],
        }
