"""Prompt leakage attack patterns.

Detects patterns that enable system prompt extraction.
"""

import re
from dataclasses import dataclass
from typing import Any, Iterator

from mass.core.types import Severity


@dataclass
class PromptLeakPattern:
    """Pattern for detecting prompt leakage vulnerabilities."""
    name: str
    pattern: str | None
    severity: Severity
    description: str
    check_type: str  # config, response, input


# Prompt leakage patterns
PROMPT_LEAK_PATTERNS = [
    PromptLeakPattern(
        name="direct_extraction_attempt",
        pattern=r"(show|print|display|reveal|output)\s+(\w+\s+)*(your|the|system)?\s*(system\s*)?prompt",
        severity=Severity.HIGH,
        description="Direct attempt to extract system prompt",
        check_type="input",
    ),
    PromptLeakPattern(
        name="indirect_extraction",
        pattern=r"(repeat|echo|recite|say)\s+(everything|all|back|what)\s+(you\s+were\s+told|instructions?)",
        severity=Severity.HIGH,
        description="Indirect attempt to extract instructions",
        check_type="input",
    ),
    PromptLeakPattern(
        name="roleplay_extraction",
        pattern=r"(pretend|act\s+as|imagine)\s+.*(leak|reveal|show).*prompt",
        severity=Severity.MEDIUM,
        description="Roleplay-based extraction attempt",
        check_type="input",
    ),
    PromptLeakPattern(
        name="json_extraction",
        pattern=r"(output|return|respond)\s+(in|as|with)\s*json.*?(system|prompt|config)",
        severity=Severity.MEDIUM,
        description="JSON format extraction attempt",
        check_type="input",
    ),
    PromptLeakPattern(
        name="prompt_in_response",
        pattern=r"(system\s*prompt|<\|?system\|?>|instructions?\s*:)",
        severity=Severity.CRITICAL,
        description="System prompt content detected in response",
        check_type="response",
    ),
    PromptLeakPattern(
        name="config_exposure",
        pattern=r"(temperature|top_p|max_tokens)\s*[=:]\s*[\d.]+",
        severity=Severity.LOW,
        description="Model configuration parameters exposed",
        check_type="response",
    ),
    PromptLeakPattern(
        name="no_prompt_protection",
        pattern=r"(protect_prompt|hide_system_prompt)\s*[=:]\s*(false|no)",
        severity=Severity.HIGH,
        description="Prompt protection is disabled",
        check_type="config",
    ),
    PromptLeakPattern(
        name="prompt_logging_enabled",
        pattern=r"(log_prompt|debug_mode)\s*[=:]\s*true",
        severity=Severity.MEDIUM,
        description="Prompt logging may expose sensitive content",
        check_type="config",
    ),
]


@dataclass
class PromptLeakFinding:
    """A prompt leakage vulnerability finding."""
    pattern_name: str
    severity: Severity
    description: str
    evidence: str
    location: str
    remediation: str = ""


class PromptLeakDetector:
    """Detects prompt leakage vulnerabilities.

    Analyzes:
    - User inputs for extraction attempts
    - Model responses for leaked content
    - Configuration for protection settings
    """

    def __init__(self, custom_patterns: list[PromptLeakPattern] | None = None):
        """Initialize detector.

        Args:
            custom_patterns: Additional patterns to use.
        """
        self.patterns = PROMPT_LEAK_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def analyze_input(self, content: str) -> Iterator[PromptLeakFinding]:
        """Analyze input for extraction attempts.

        Args:
            content: User input to analyze.

        Yields:
            PromptLeakFinding for each detection.
        """
        for pattern in self.patterns:
            if pattern.check_type != "input" or not pattern.pattern:
                continue

            regex = re.compile(pattern.pattern, re.IGNORECASE)
            for match in regex.finditer(content):
                yield PromptLeakFinding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    evidence=match.group(0)[:200],
                    location="user_input",
                    remediation=self._get_remediation(pattern.name),
                )

    def analyze_response(
        self,
        content: str,
        system_prompt: str | None = None,
    ) -> Iterator[PromptLeakFinding]:
        """Analyze response for leaked prompt content.

        Args:
            content: Model response to analyze.
            system_prompt: Optional system prompt to check for leakage.

        Yields:
            PromptLeakFinding for each detection.
        """
        for pattern in self.patterns:
            if pattern.check_type != "response" or not pattern.pattern:
                continue

            regex = re.compile(pattern.pattern, re.IGNORECASE)
            for match in regex.finditer(content):
                yield PromptLeakFinding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    evidence=match.group(0)[:200],
                    location="model_response",
                    remediation=self._get_remediation(pattern.name),
                )

        # Check for actual system prompt content in response
        if system_prompt:
            yield from self._check_prompt_leakage(content, system_prompt)

    def _check_prompt_leakage(
        self,
        response: str,
        system_prompt: str,
    ) -> Iterator[PromptLeakFinding]:
        """Check if response contains system prompt content.

        Args:
            response: Model response.
            system_prompt: System prompt to check against.

        Yields:
            Findings for leaked content.
        """
        # Split prompt into significant phrases
        prompt_lower = system_prompt.lower()
        response_lower = response.lower()

        # Check for exact matches of significant chunks
        words = system_prompt.split()
        chunk_size = min(5, len(words))

        for i in range(len(words) - chunk_size + 1):
            chunk = " ".join(words[i:i + chunk_size]).lower()
            if len(chunk) > 20 and chunk in response_lower:
                yield PromptLeakFinding(
                    pattern_name="prompt_content_leaked",
                    severity=Severity.CRITICAL,
                    description="System prompt content found in response",
                    evidence=chunk[:100],
                    location="model_response",
                    remediation="Add output filtering to remove prompt content",
                )
                break

    def analyze_config(
        self,
        config: dict[str, Any] | str,
    ) -> Iterator[PromptLeakFinding]:
        """Analyze configuration for leakage vulnerabilities.

        Args:
            config: Configuration dict or string.

        Yields:
            PromptLeakFinding for each issue.
        """
        if isinstance(config, dict):
            config_str = str(config)
        else:
            config_str = config

        for pattern in self.patterns:
            if pattern.check_type != "config" or not pattern.pattern:
                continue

            regex = re.compile(pattern.pattern, re.IGNORECASE)
            for match in regex.finditer(config_str):
                yield PromptLeakFinding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    evidence=match.group(0)[:200],
                    location="configuration",
                    remediation=self._get_remediation(pattern.name),
                )

        # Check for missing protections
        if isinstance(config, dict):
            yield from self._check_missing_protections(config)

    def _check_missing_protections(
        self,
        config: dict[str, Any],
    ) -> Iterator[PromptLeakFinding]:
        """Check for missing prompt protection settings.

        Args:
            config: Configuration dict.

        Yields:
            Findings for missing protections.
        """
        if not config.get("protect_prompt", True):
            yield PromptLeakFinding(
                pattern_name="unprotected_prompt",
                severity=Severity.HIGH,
                description="Prompt protection is not enabled",
                evidence="protect_prompt: false",
                location="configuration",
                remediation="Enable prompt protection in configuration",
            )

        if not config.get("filter_prompt_from_output", True):
            yield PromptLeakFinding(
                pattern_name="no_output_filter",
                severity=Severity.MEDIUM,
                description="Output filtering for prompt content not enabled",
                evidence="filter_prompt_from_output: false",
                location="configuration",
                remediation="Enable output filtering to prevent prompt leakage",
            )

    def _get_remediation(self, pattern_name: str) -> str:
        """Get remediation suggestion for a pattern.

        Args:
            pattern_name: Name of the pattern.

        Returns:
            Remediation suggestion.
        """
        remediations = {
            "direct_extraction_attempt": "Add input filtering for extraction attempts",
            "indirect_extraction": "Filter requests to repeat/echo instructions",
            "roleplay_extraction": "Limit roleplay capabilities near prompt content",
            "json_extraction": "Sanitize JSON output format requests",
            "prompt_in_response": "Add output filtering to remove prompt markers",
            "config_exposure": "Remove configuration details from responses",
            "no_prompt_protection": "Enable prompt protection in configuration",
            "prompt_logging_enabled": "Disable prompt logging or secure logs",
            "prompt_content_leaked": "Add comprehensive output filtering",
            "unprotected_prompt": "Enable all prompt protection features",
        }

        return remediations.get(pattern_name, "Review prompt security settings")
