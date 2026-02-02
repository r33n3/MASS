"""RAG poisoning attack patterns.

Detects patterns that enable RAG document poisoning attacks.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from mass.core.types import Severity


@dataclass
class RAGPoisoningPattern:
    """Pattern for detecting RAG poisoning vulnerabilities."""
    name: str
    pattern: str
    severity: Severity
    description: str
    indicator_type: str  # document_content, retrieval_config, embedding_config

    @property
    def compiled_pattern(self) -> re.Pattern:
        """Get compiled regex pattern."""
        return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)


# RAG poisoning patterns
RAG_POISONING_PATTERNS = [
    RAGPoisoningPattern(
        name="instruction_injection",
        pattern=r"(ignore|disregard|forget)\s+(\w+\s+)*(previous|all|prior)\s+(\w+\s+)*(instructions?|context)",
        severity=Severity.CRITICAL,
        description="Document contains instruction override attempt",
        indicator_type="document_content",
    ),
    RAGPoisoningPattern(
        name="role_manipulation",
        pattern=r"(you\s+are|act\s+as|pretend\s+to\s+be)\s+(a|an)?\s*(new|different|evil)",
        severity=Severity.HIGH,
        description="Document attempts to manipulate AI role",
        indicator_type="document_content",
    ),
    RAGPoisoningPattern(
        name="hidden_instruction",
        pattern=r"(<!--.*?-->|<\s*script.*?>.*?<\s*/script\s*>|\[hidden\]|\{%.*?%\})",
        severity=Severity.HIGH,
        description="Document contains hidden content that may be processed",
        indicator_type="document_content",
    ),
    RAGPoisoningPattern(
        name="context_escape",
        pattern=r"(</?\s*(context|document|system|user|assistant)\s*>)",
        severity=Severity.HIGH,
        description="Document contains context boundary markers",
        indicator_type="document_content",
    ),
    RAGPoisoningPattern(
        name="unicode_manipulation",
        pattern=r"[\u200b-\u200f\u202a-\u202e\ufeff]",
        severity=Severity.MEDIUM,
        description="Document contains invisible unicode characters",
        indicator_type="document_content",
    ),
    RAGPoisoningPattern(
        name="no_document_filtering",
        pattern=r"(content_filter\s*[=:]\s*(false|none)|skip_validation\s*[=:]\s*true)",
        severity=Severity.HIGH,
        description="RAG configuration disables document filtering",
        indicator_type="retrieval_config",
    ),
    RAGPoisoningPattern(
        name="high_chunk_overlap",
        pattern=r"chunk_overlap\s*[=:]\s*(\d{3,})",
        severity=Severity.LOW,
        description="High chunk overlap may spread poisoned content",
        indicator_type="retrieval_config",
    ),
    RAGPoisoningPattern(
        name="untrusted_source",
        pattern=r"(url|path|source)\s*[=:]\s*['\"]?(http://|ftp://|file://)",
        severity=Severity.MEDIUM,
        description="RAG uses potentially untrusted data source",
        indicator_type="retrieval_config",
    ),
]


@dataclass
class RAGPoisoningFinding:
    """A RAG poisoning vulnerability finding."""
    pattern_name: str
    severity: Severity
    description: str
    location: str
    evidence: str
    remediation: str = ""


class RAGPoisoningDetector:
    """Detects RAG poisoning vulnerabilities.

    Analyzes:
    - Document content for injection payloads
    - RAG configuration for security issues
    - Embedding and retrieval settings
    """

    def __init__(self, custom_patterns: list[RAGPoisoningPattern] | None = None):
        """Initialize detector.

        Args:
            custom_patterns: Additional patterns to use.
        """
        self.patterns = RAG_POISONING_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def analyze_document(
        self,
        content: str,
        source: str = "document",
    ) -> Iterator[RAGPoisoningFinding]:
        """Analyze document content for poisoning patterns.

        Args:
            content: Document content to analyze.
            source: Source identifier.

        Yields:
            RAGPoisoningFinding for each match.
        """
        for pattern in self.patterns:
            if pattern.indicator_type != "document_content":
                continue

            for match in pattern.compiled_pattern.finditer(content):
                yield RAGPoisoningFinding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    location=source,
                    evidence=match.group(0)[:200],
                    remediation=self._get_remediation(pattern.name),
                )

    def analyze_config(
        self,
        config: dict[str, Any] | str,
        source: str = "config",
    ) -> Iterator[RAGPoisoningFinding]:
        """Analyze RAG configuration for security issues.

        Args:
            config: Configuration dict or string.
            source: Source identifier.

        Yields:
            RAGPoisoningFinding for each issue.
        """
        if isinstance(config, dict):
            config_str = str(config)
        else:
            config_str = config

        for pattern in self.patterns:
            if pattern.indicator_type not in ("retrieval_config", "embedding_config"):
                continue

            for match in pattern.compiled_pattern.finditer(config_str):
                yield RAGPoisoningFinding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    location=source,
                    evidence=match.group(0)[:200],
                    remediation=self._get_remediation(pattern.name),
                )

        # Check for missing security settings
        if isinstance(config, dict):
            yield from self._check_config_settings(config, source)

    def _check_config_settings(
        self,
        config: dict[str, Any],
        source: str,
    ) -> Iterator[RAGPoisoningFinding]:
        """Check for missing security settings in config.

        Args:
            config: Configuration dict.
            source: Source identifier.

        Yields:
            Findings for missing settings.
        """
        # Check for missing content filtering
        if not config.get("content_filter", True):
            yield RAGPoisoningFinding(
                pattern_name="missing_content_filter",
                severity=Severity.HIGH,
                description="Content filtering is disabled",
                location=source,
                evidence="content_filter: false",
                remediation="Enable content filtering for retrieved documents",
            )

        # Check for missing source validation
        if not config.get("validate_sources", True):
            yield RAGPoisoningFinding(
                pattern_name="missing_source_validation",
                severity=Severity.MEDIUM,
                description="Source validation is disabled",
                location=source,
                evidence="validate_sources: false",
                remediation="Enable source validation to verify document origins",
            )

        # Check chunk size
        chunk_size = config.get("chunk_size", 1000)
        if chunk_size > 5000:
            yield RAGPoisoningFinding(
                pattern_name="large_chunk_size",
                severity=Severity.LOW,
                description="Large chunk size may include more poisoned content",
                location=source,
                evidence=f"chunk_size: {chunk_size}",
                remediation="Consider smaller chunk sizes to limit injection scope",
            )

    def _get_remediation(self, pattern_name: str) -> str:
        """Get remediation suggestion for a pattern.

        Args:
            pattern_name: Name of the pattern.

        Returns:
            Remediation suggestion.
        """
        remediations = {
            "instruction_injection": "Sanitize document content and add output filtering",
            "role_manipulation": "Filter documents for role manipulation attempts",
            "hidden_instruction": "Strip hidden content from documents before indexing",
            "context_escape": "Escape or remove context boundary markers",
            "unicode_manipulation": "Normalize unicode in documents",
            "no_document_filtering": "Enable content filtering in RAG configuration",
            "high_chunk_overlap": "Reduce chunk overlap to limit spread of poisoned content",
            "untrusted_source": "Validate and restrict document sources",
        }

        return remediations.get(pattern_name, "Review and sanitize RAG documents")
