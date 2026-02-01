"""Entropy-based secret detection.

Uses Shannon entropy to identify high-randomness strings that may be secrets.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass


# Character sets for entropy calculation
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "0123456789abcdefABCDEF"
ALPHANUMERIC_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


@dataclass
class EntropyResult:
    """Result of entropy analysis."""
    text: str
    entropy: float
    charset_type: str
    is_high_entropy: bool
    threshold: float


class EntropyAnalyzer:
    """Analyzes strings for high entropy that may indicate secrets."""

    # Default entropy thresholds
    DEFAULT_BASE64_THRESHOLD = 4.5
    DEFAULT_HEX_THRESHOLD = 3.0
    DEFAULT_GENERAL_THRESHOLD = 4.0

    # Minimum string length to analyze
    MIN_LENGTH = 8

    # Common false positive patterns
    FALSE_POSITIVE_PATTERNS = [
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",  # UUID
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",  # ISO timestamp
        r"^v?\d+\.\d+\.\d+",  # Semantic version
        r"^[a-z]+_[a-z]+_[a-z]+$",  # Snake case names
        r"^[A-Z][a-z]+[A-Z][a-z]+",  # CamelCase names
        r"^https?://",  # URLs (handled separately)
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",  # Email
        r"^\$\{.*\}$",  # Environment variable reference
        r"^{{.*}}$",  # Template variable
        r"^<.*>$",  # Placeholder
    ]

    def __init__(
        self,
        base64_threshold: float | None = None,
        hex_threshold: float | None = None,
        general_threshold: float | None = None,
        min_length: int | None = None,
    ):
        """Initialize entropy analyzer.

        Args:
            base64_threshold: Entropy threshold for base64-like strings.
            hex_threshold: Entropy threshold for hex strings.
            general_threshold: Entropy threshold for general strings.
            min_length: Minimum string length to analyze.
        """
        self.base64_threshold = base64_threshold or self.DEFAULT_BASE64_THRESHOLD
        self.hex_threshold = hex_threshold or self.DEFAULT_HEX_THRESHOLD
        self.general_threshold = general_threshold or self.DEFAULT_GENERAL_THRESHOLD
        self.min_length = min_length or self.MIN_LENGTH

        self._false_positive_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.FALSE_POSITIVE_PATTERNS
        ]

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            text: String to analyze.

        Returns:
            Shannon entropy value (bits per character).
        """
        if not text:
            return 0.0

        # Count character frequencies
        freq = Counter(text)
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def detect_charset(self, text: str) -> str:
        """Detect the character set type of a string.

        Args:
            text: String to analyze.

        Returns:
            Character set type: 'hex', 'base64', or 'general'.
        """
        # Check if hex
        if all(c in HEX_CHARS for c in text):
            return "hex"

        # Check if base64-like
        if all(c in BASE64_CHARS for c in text):
            return "base64"

        return "general"

    def get_threshold(self, charset_type: str) -> float:
        """Get the entropy threshold for a character set type.

        Args:
            charset_type: Character set type.

        Returns:
            Entropy threshold.
        """
        if charset_type == "hex":
            return self.hex_threshold
        elif charset_type == "base64":
            return self.base64_threshold
        return self.general_threshold

    def is_false_positive(self, text: str) -> bool:
        """Check if a string matches known false positive patterns.

        Args:
            text: String to check.

        Returns:
            True if likely a false positive.
        """
        for pattern in self._false_positive_patterns:
            if pattern.match(text):
                return True
        return False

    def analyze(self, text: str, custom_threshold: float | None = None) -> EntropyResult:
        """Analyze a string for high entropy.

        Args:
            text: String to analyze.
            custom_threshold: Optional custom entropy threshold.

        Returns:
            EntropyResult with analysis details.
        """
        entropy = self.calculate_entropy(text)
        charset_type = self.detect_charset(text)
        threshold = custom_threshold or self.get_threshold(charset_type)

        is_high_entropy = (
            len(text) >= self.min_length
            and entropy >= threshold
            and not self.is_false_positive(text)
        )

        return EntropyResult(
            text=text,
            entropy=entropy,
            charset_type=charset_type,
            is_high_entropy=is_high_entropy,
            threshold=threshold,
        )

    def find_high_entropy_strings(
        self,
        content: str,
        min_length: int | None = None,
    ) -> list[EntropyResult]:
        """Find all high-entropy strings in content.

        Args:
            content: Content to search.
            min_length: Minimum string length to consider.

        Returns:
            List of high-entropy strings found.
        """
        min_len = min_length or self.min_length
        results = []

        # Pattern to find potential secrets (continuous alphanumeric/special chars)
        pattern = re.compile(r"[A-Za-z0-9+/=_\-]{" + str(min_len) + r",}")

        for match in pattern.finditer(content):
            text = match.group()
            result = self.analyze(text)
            if result.is_high_entropy:
                results.append(result)

        return results

    def analyze_key_value(
        self,
        key: str,
        value: str,
    ) -> EntropyResult | None:
        """Analyze a key-value pair for potential secrets.

        Secret-like keys get a lower entropy threshold.

        Args:
            key: The key/variable name.
            value: The value to analyze.

        Returns:
            EntropyResult if value appears to be a secret, None otherwise.
        """
        # Keywords that suggest the value might be a secret
        secret_keywords = {
            "key", "secret", "password", "passwd", "pwd", "token",
            "auth", "credential", "api", "private", "access",
        }

        # Check if key contains secret keywords
        key_lower = key.lower()
        is_secret_key = any(kw in key_lower for kw in secret_keywords)

        if len(value) < self.min_length:
            return None

        result = self.analyze(value)

        # Lower threshold for values with secret-like keys
        if is_secret_key:
            adjusted_threshold = result.threshold * 0.8
            is_high_entropy = (
                result.entropy >= adjusted_threshold
                and not self.is_false_positive(value)
            )
            return EntropyResult(
                text=value,
                entropy=result.entropy,
                charset_type=result.charset_type,
                is_high_entropy=is_high_entropy,
                threshold=adjusted_threshold,
            )

        return result if result.is_high_entropy else None


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string.

    Convenience function for simple entropy calculation.

    Args:
        text: String to analyze.

    Returns:
        Shannon entropy value.
    """
    analyzer = EntropyAnalyzer()
    return analyzer.calculate_entropy(text)
