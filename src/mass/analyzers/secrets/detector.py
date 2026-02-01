"""Secret detector.

Main secret detection engine that combines pattern matching, entropy analysis,
and validation to detect exposed secrets in code and configuration.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from mass.core.types import Severity as CoreSeverity
from mass.analyzers.secrets.patterns import (
    SECRET_PATTERNS,
    SecretPattern,
    SecretCategory,
    Severity,
)
from mass.analyzers.secrets.entropy import EntropyAnalyzer
from mass.analyzers.secrets.validators import validate_secret, ValidationResult

logger = logging.getLogger(__name__)


@dataclass
class SecretMatch:
    """A detected secret match."""
    pattern_name: str
    category: SecretCategory
    severity: Severity
    description: str
    value: str
    masked_value: str
    file_path: Path | None
    line_number: int | None
    line_content: str
    confidence: float
    entropy: float | None = None
    validation: ValidationResult | None = None
    context: dict = field(default_factory=dict)

    @property
    def core_severity(self) -> CoreSeverity:
        """Convert to core severity type."""
        mapping = {
            Severity.CRITICAL: CoreSeverity.CRITICAL,
            Severity.HIGH: CoreSeverity.HIGH,
            Severity.MEDIUM: CoreSeverity.MEDIUM,
            Severity.LOW: CoreSeverity.LOW,
        }
        return mapping.get(self.severity, CoreSeverity.MEDIUM)


@dataclass
class DetectionResult:
    """Result of secret detection scan."""
    secrets: list[SecretMatch] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def has_secrets(self) -> bool:
        """Check if any secrets were found."""
        return len(self.secrets) > 0

    @property
    def critical_count(self) -> int:
        """Count of critical severity secrets."""
        return sum(1 for s in self.secrets if s.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity secrets."""
        return sum(1 for s in self.secrets if s.severity == Severity.HIGH)

    def by_severity(self, severity: Severity) -> list[SecretMatch]:
        """Get secrets by severity."""
        return [s for s in self.secrets if s.severity == severity]

    def by_category(self, category: SecretCategory) -> list[SecretMatch]:
        """Get secrets by category."""
        return [s for s in self.secrets if s.category == category]


class SecretDetector:
    """Detects exposed secrets in code and configuration files.

    Combines multiple detection methods:
    1. Pattern matching against known secret formats
    2. Entropy analysis for high-randomness strings
    3. Validation to reduce false positives
    """

    # File extensions to skip
    SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
        ".mp3", ".mp4", ".wav", ".avi", ".mov",
        ".zip", ".tar", ".gz", ".rar", ".7z",
        ".exe", ".dll", ".so", ".dylib",
        ".pyc", ".pyo", ".class",
        ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    }

    # Directories to skip
    SKIP_DIRECTORIES = {
        ".git", ".svn", ".hg",
        "__pycache__", ".pytest_cache", ".mypy_cache",
        "node_modules", ".npm",
        "venv", ".venv", "env", ".env.example",
        ".tox", ".nox",
        "dist", "build", "target",
        "coverage", ".coverage",
    }

    # Files to skip
    SKIP_FILES = {
        ".gitignore", ".dockerignore",
        "package-lock.json", "yarn.lock", "poetry.lock",
        "Pipfile.lock", "requirements-lock.txt",
    }

    def __init__(
        self,
        patterns: list[SecretPattern] | None = None,
        use_entropy: bool = True,
        entropy_threshold: float = 4.5,
        validate_secrets: bool = True,
        include_low_confidence: bool = False,
        min_confidence: float = 0.5,
    ):
        """Initialize secret detector.

        Args:
            patterns: Custom patterns to use. Uses defaults if None.
            use_entropy: Enable entropy-based detection.
            entropy_threshold: Minimum entropy for high-entropy detection.
            validate_secrets: Enable secret validation.
            include_low_confidence: Include low confidence matches.
            min_confidence: Minimum confidence threshold.
        """
        self.patterns = patterns or SECRET_PATTERNS
        self.use_entropy = use_entropy
        self.entropy_threshold = entropy_threshold
        self.validate_secrets = validate_secrets
        self.include_low_confidence = include_low_confidence
        self.min_confidence = min_confidence

        self.entropy_analyzer = EntropyAnalyzer(
            base64_threshold=entropy_threshold,
            hex_threshold=3.0,
            general_threshold=entropy_threshold,
        )

    def scan_content(
        self,
        content: str,
        file_path: Path | None = None,
    ) -> DetectionResult:
        """Scan content for secrets.

        Args:
            content: Content to scan.
            file_path: Optional file path for context.

        Returns:
            DetectionResult with found secrets.
        """
        result = DetectionResult()
        lines = content.splitlines()
        result.lines_scanned = len(lines)

        # Track unique secrets to avoid duplicates
        seen_secrets: set[str] = set()

        # Pattern-based detection
        for pattern in self.patterns:
            for match in self._find_pattern_matches(content, pattern, lines, file_path):
                if match.value not in seen_secrets:
                    seen_secrets.add(match.value)
                    result.secrets.append(match)

        # Entropy-based detection
        if self.use_entropy:
            for match in self._find_entropy_matches(content, lines, file_path):
                if match.value not in seen_secrets:
                    seen_secrets.add(match.value)
                    result.secrets.append(match)

        # Filter by confidence if needed
        if not self.include_low_confidence:
            result.secrets = [
                s for s in result.secrets if s.confidence >= self.min_confidence
            ]

        return result

    def scan_file(self, file_path: Path) -> DetectionResult:
        """Scan a single file for secrets.

        Args:
            file_path: Path to the file.

        Returns:
            DetectionResult with found secrets.
        """
        result = DetectionResult(files_scanned=1)

        # Check if file should be skipped
        if self._should_skip_file(file_path):
            return result

        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = file_path.read_text(encoding="latin-1")
            except Exception as e:
                result.errors.append(f"Could not read {file_path}: {e}")
                return result
        except Exception as e:
            result.errors.append(f"Error reading {file_path}: {e}")
            return result

        scan_result = self.scan_content(content, file_path)
        result.secrets = scan_result.secrets
        result.lines_scanned = scan_result.lines_scanned

        return result

    def scan_directory(
        self,
        directory: Path,
        recursive: bool = True,
    ) -> DetectionResult:
        """Scan a directory for secrets.

        Args:
            directory: Directory to scan.
            recursive: Scan subdirectories.

        Returns:
            DetectionResult with all found secrets.
        """
        result = DetectionResult()

        for file_path in self._iter_files(directory, recursive):
            file_result = self.scan_file(file_path)
            result.files_scanned += file_result.files_scanned
            result.lines_scanned += file_result.lines_scanned
            result.secrets.extend(file_result.secrets)
            result.errors.extend(file_result.errors)

        return result

    def _find_pattern_matches(
        self,
        content: str,
        pattern: SecretPattern,
        lines: list[str],
        file_path: Path | None,
    ) -> Iterator[SecretMatch]:
        """Find matches for a specific pattern.

        Args:
            content: Content to search.
            pattern: Pattern to match.
            lines: Content split into lines.
            file_path: Optional file path.

        Yields:
            SecretMatch for each match found.
        """
        compiled = pattern.compiled_pattern

        for match in compiled.finditer(content):
            secret_value = match.group(0)

            # Skip false positives
            if self._is_false_positive(secret_value, pattern):
                continue

            # Find line number
            line_num, line_content = self._find_line(content, match.start(), lines)

            # Calculate entropy
            entropy = self.entropy_analyzer.calculate_entropy(secret_value)

            # Check entropy threshold if specified
            if pattern.entropy_threshold and entropy < pattern.entropy_threshold:
                continue

            # Validate if enabled
            validation = None
            confidence = 0.8

            if self.validate_secrets:
                validation = validate_secret(secret_value, pattern.validators)
                if validation.is_valid:
                    confidence = validation.confidence
                else:
                    continue  # Skip invalid matches

            yield SecretMatch(
                pattern_name=pattern.name,
                category=pattern.category,
                severity=pattern.severity,
                description=pattern.description,
                value=secret_value,
                masked_value=self._mask_secret(secret_value),
                file_path=file_path,
                line_number=line_num,
                line_content=line_content,
                confidence=confidence,
                entropy=entropy,
                validation=validation,
            )

    def _find_entropy_matches(
        self,
        content: str,
        lines: list[str],
        file_path: Path | None,
    ) -> Iterator[SecretMatch]:
        """Find high-entropy strings that might be secrets.

        Args:
            content: Content to search.
            lines: Content split into lines.
            file_path: Optional file path.

        Yields:
            SecretMatch for each high-entropy string found.
        """
        high_entropy_strings = self.entropy_analyzer.find_high_entropy_strings(content)

        for result in high_entropy_strings:
            # Find position in content
            pos = content.find(result.text)
            if pos == -1:
                continue

            line_num, line_content = self._find_line(content, pos, lines)

            yield SecretMatch(
                pattern_name="high_entropy_string",
                category=SecretCategory.GENERIC,
                severity=Severity.LOW,
                description="High entropy string (potential secret)",
                value=result.text,
                masked_value=self._mask_secret(result.text),
                file_path=file_path,
                line_number=line_num,
                line_content=line_content,
                confidence=0.4,
                entropy=result.entropy,
                context={"charset_type": result.charset_type},
            )

    def _find_line(
        self,
        content: str,
        pos: int,
        lines: list[str],
    ) -> tuple[int, str]:
        """Find the line number and content for a position.

        Args:
            content: Full content.
            pos: Position in content.
            lines: Content split into lines.

        Returns:
            Tuple of (line_number, line_content).
        """
        line_num = content[:pos].count("\n") + 1
        if 0 < line_num <= len(lines):
            line_content = lines[line_num - 1]
        else:
            line_content = ""
        return line_num, line_content

    def _mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """Mask a secret value for safe display.

        Args:
            secret: Secret to mask.
            visible_chars: Number of characters to show at start/end.

        Returns:
            Masked secret string.
        """
        if len(secret) <= visible_chars * 2 + 4:
            return "*" * len(secret)

        return f"{secret[:visible_chars]}...{secret[-visible_chars:]}"

    def _is_false_positive(self, value: str, pattern: SecretPattern) -> bool:
        """Check if a match is a false positive.

        Args:
            value: Matched value.
            pattern: Pattern that matched.

        Returns:
            True if likely a false positive.
        """
        # Check pattern-specific false positive patterns
        for fp_pattern in pattern.false_positive_patterns:
            if re.search(fp_pattern, value, re.IGNORECASE):
                return True

        # Check for common false positive indicators
        false_positive_indicators = [
            "example", "test", "sample", "demo", "placeholder",
            "your_", "xxx", "abc", "123", "fake", "mock",
        ]

        value_lower = value.lower()
        for indicator in false_positive_indicators:
            if indicator in value_lower:
                return True

        return False

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if a file should be skipped.

        Args:
            file_path: Path to check.

        Returns:
            True if file should be skipped.
        """
        # Check extension
        if file_path.suffix.lower() in self.SKIP_EXTENSIONS:
            return True

        # Check filename
        if file_path.name in self.SKIP_FILES:
            return True

        return False

    def _should_skip_directory(self, dir_path: Path) -> bool:
        """Check if a directory should be skipped.

        Args:
            dir_path: Directory to check.

        Returns:
            True if directory should be skipped.
        """
        return dir_path.name in self.SKIP_DIRECTORIES

    def _iter_files(
        self,
        directory: Path,
        recursive: bool,
    ) -> Iterator[Path]:
        """Iterate over files in a directory.

        Args:
            directory: Directory to iterate.
            recursive: Include subdirectories.

        Yields:
            File paths.
        """
        try:
            for entry in directory.iterdir():
                if entry.is_file():
                    if not self._should_skip_file(entry):
                        yield entry
                elif entry.is_dir() and recursive:
                    if not self._should_skip_directory(entry):
                        yield from self._iter_files(entry, recursive)
        except PermissionError:
            logger.debug(f"Permission denied: {directory}")
        except Exception as e:
            logger.debug(f"Error reading directory {directory}: {e}")
