"""Tests for secret detection."""

import tempfile
from pathlib import Path

import pytest

from mass.analyzers.secrets.patterns import (
    SECRET_PATTERNS,
    SecretPattern,
    SecretCategory,
    Severity,
    get_patterns_by_category,
    get_critical_patterns,
)
from mass.analyzers.secrets.entropy import EntropyAnalyzer, shannon_entropy
from mass.analyzers.secrets.validators import (
    OpenAIKeyValidator,
    GitHubTokenValidator,
    JWTValidator,
    ValidatorRegistry,
    validate_secret,
)
from mass.analyzers.secrets.detector import SecretDetector


class TestSecretPatterns:
    """Tests for secret patterns."""

    def test_patterns_exist(self) -> None:
        """Test that patterns are defined."""
        assert len(SECRET_PATTERNS) >= 50

    def test_pattern_structure(self) -> None:
        """Test pattern structure is valid."""
        for pattern in SECRET_PATTERNS:
            assert pattern.name
            assert pattern.pattern
            assert isinstance(pattern.category, SecretCategory)
            assert isinstance(pattern.severity, Severity)
            assert pattern.description

    def test_get_patterns_by_category(self) -> None:
        """Test filtering patterns by category."""
        ai_patterns = get_patterns_by_category(SecretCategory.AI_PROVIDER)
        assert len(ai_patterns) > 0
        assert all(p.category == SecretCategory.AI_PROVIDER for p in ai_patterns)

    def test_get_critical_patterns(self) -> None:
        """Test getting critical patterns."""
        critical = get_critical_patterns()
        assert len(critical) > 0
        assert all(p.severity == Severity.CRITICAL for p in critical)

    def test_openai_pattern_matches(self) -> None:
        """Test OpenAI key pattern matching."""
        # Find OpenAI pattern
        openai_pattern = next(
            (p for p in SECRET_PATTERNS if p.name == "openai_api_key"),
            None
        )
        assert openai_pattern is not None

        # Test valid key format
        regex = openai_pattern.compiled_pattern
        assert regex.search("sk-" + "a" * 48)
        assert not regex.search("sk-short")

    def test_github_pattern_matches(self) -> None:
        """Test GitHub token pattern matching."""
        github_pattern = next(
            (p for p in SECRET_PATTERNS if p.name == "github_pat"),
            None
        )
        assert github_pattern is not None

        regex = github_pattern.compiled_pattern
        assert regex.search("ghp_" + "a" * 36)
        assert not regex.search("ghp_short")


class TestEntropyAnalyzer:
    """Tests for entropy analysis."""

    def test_calculate_entropy(self) -> None:
        """Test entropy calculation."""
        analyzer = EntropyAnalyzer()

        # Low entropy - repeated characters
        low_entropy = analyzer.calculate_entropy("aaaaaaaaaa")
        assert low_entropy == 0.0

        # Higher entropy - random string
        high_entropy = analyzer.calculate_entropy("aB1cD2eF3g")
        assert high_entropy > 3.0

    def test_detect_charset(self) -> None:
        """Test character set detection."""
        analyzer = EntropyAnalyzer()

        assert analyzer.detect_charset("0123456789abcdef") == "hex"
        assert analyzer.detect_charset("ABCDabcd1234+/==") == "base64"
        assert analyzer.detect_charset("Hello World!") == "general"

    def test_analyze_string(self) -> None:
        """Test string analysis."""
        analyzer = EntropyAnalyzer()

        # High entropy random string
        result = analyzer.analyze("Kx9mP2nQ4rS6tU8vW0yA1bC3dE5fG7hI")
        assert result.entropy > 4.0

        # Low entropy repeated pattern
        result = analyzer.analyze("abcabcabc")
        assert result.entropy < 2.0

    def test_is_false_positive(self) -> None:
        """Test false positive detection."""
        analyzer = EntropyAnalyzer()

        assert analyzer.is_false_positive("123e4567-e89b-12d3-a456-426614174000")  # UUID
        assert analyzer.is_false_positive("2024-01-15T10:30:00Z")  # Timestamp
        assert analyzer.is_false_positive("v1.2.3")  # Version
        assert not analyzer.is_false_positive("Kx9mP2nQ4rS6tU8v")  # Random

    def test_find_high_entropy_strings(self) -> None:
        """Test finding high entropy strings in content."""
        analyzer = EntropyAnalyzer()

        content = """
        API_KEY = "Kx9mP2nQ4rS6tU8vW0yA1bC3dE5fG7hI"
        username = "admin"
        """

        results = analyzer.find_high_entropy_strings(content)
        # Should find the random-looking API key
        assert len(results) >= 1

    def test_shannon_entropy_function(self) -> None:
        """Test convenience entropy function."""
        entropy = shannon_entropy("random_string_123")
        assert entropy > 0


class TestSecretValidators:
    """Tests for secret validators."""

    def test_openai_validator(self) -> None:
        """Test OpenAI key validator."""
        validator = OpenAIKeyValidator()

        # Valid format
        result = validator.validate("sk-" + "a" * 48)
        assert result.is_valid
        assert result.confidence >= 0.9

        # Invalid format
        result = validator.validate("invalid-key")
        assert not result.is_valid

    def test_github_validator(self) -> None:
        """Test GitHub token validator."""
        validator = GitHubTokenValidator()

        # Valid PAT
        result = validator.validate("ghp_" + "a" * 36)
        assert result.is_valid
        assert "ghp" in result.message.lower()

        # Valid OAuth
        result = validator.validate("gho_" + "a" * 36)
        assert result.is_valid

        # Invalid
        result = validator.validate("invalid")
        assert not result.is_valid

    def test_jwt_validator(self) -> None:
        """Test JWT validator."""
        validator = JWTValidator()

        # Valid JWT format (header.payload.signature)
        valid_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = validator.validate(valid_jwt)
        assert result.is_valid

        # Invalid
        result = validator.validate("not.a.jwt")
        assert not result.is_valid

    def test_validator_registry(self) -> None:
        """Test validator registry."""
        registry = ValidatorRegistry()

        assert registry.get("openai") is not None
        assert registry.get("github") is not None
        assert registry.get("nonexistent") is None

    def test_validate_secret_function(self) -> None:
        """Test convenience validate function."""
        result = validate_secret("ghp_" + "a" * 36, ["github"])
        assert result.is_valid


class TestSecretDetector:
    """Tests for SecretDetector."""

    def test_scan_content_with_secrets(self) -> None:
        """Test scanning content with secrets."""
        detector = SecretDetector()

        content = '''
        OPENAI_API_KEY = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        GITHUB_TOKEN = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        '''

        result = detector.scan_content(content)
        assert result.has_secrets
        assert len(result.secrets) >= 1

    def test_scan_content_without_secrets(self) -> None:
        """Test scanning content without secrets."""
        detector = SecretDetector()

        content = '''
        def hello():
            print("Hello, World!")
        '''

        result = detector.scan_content(content)
        # May have some low-confidence matches, filter by confidence
        high_confidence = [s for s in result.secrets if s.confidence >= 0.7]
        assert len(high_confidence) == 0

    def test_scan_file(self) -> None:
        """Test scanning a file."""
        detector = SecretDetector()

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
        ) as f:
            f.write('API_KEY = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"')
            f.flush()

            result = detector.scan_file(Path(f.name))
            assert result.files_scanned == 1
            assert result.has_secrets

    def test_scan_directory(self) -> None:
        """Test scanning a directory."""
        detector = SecretDetector()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create a file with a secret
            (base / "config.py").write_text(
                'SECRET = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
            )

            # Create a file without secrets
            (base / "main.py").write_text('print("hello")')

            result = detector.scan_directory(base)
            assert result.files_scanned >= 2
            assert result.has_secrets

    def test_skip_binary_files(self) -> None:
        """Test that binary files are skipped."""
        detector = SecretDetector()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create a binary file
            (base / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")

            result = detector.scan_directory(base)
            # Should not error or find secrets in binary
            assert not result.has_secrets

    def test_mask_secret(self) -> None:
        """Test secret masking."""
        detector = SecretDetector()

        # Long secret
        masked = detector._mask_secret("abcdefghijklmnopqrstuvwxyz")
        assert "abcd" in masked
        assert "wxyz" in masked
        assert "..." in masked

        # Short secret
        masked = detector._mask_secret("short")
        assert masked == "*****"

    def test_detection_result_properties(self) -> None:
        """Test DetectionResult properties."""
        detector = SecretDetector()

        content = '''
        sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        '''

        result = detector.scan_content(content)

        # Test severity filtering
        critical = result.by_severity(Severity.CRITICAL)
        assert all(s.severity == Severity.CRITICAL for s in critical)

    def test_entropy_detection_disabled(self) -> None:
        """Test with entropy detection disabled."""
        detector = SecretDetector(use_entropy=False)

        content = "RandomHighEntropyString123456789ABCDEFGhijklmnop"

        result = detector.scan_content(content)
        # Without pattern match and with entropy disabled, should find less
        entropy_matches = [
            s for s in result.secrets
            if s.pattern_name == "high_entropy_string"
        ]
        assert len(entropy_matches) == 0

    def test_false_positive_detection(self) -> None:
        """Test false positive detection."""
        detector = SecretDetector()

        # These should be detected as false positives
        content = '''
        example_key = "example123456789"
        test_token = "test_fake_token"
        placeholder = "<YOUR_API_KEY>"
        '''

        result = detector.scan_content(content)
        # Should have low confidence or no matches
        high_confidence = [s for s in result.secrets if s.confidence >= 0.8]
        assert len(high_confidence) == 0
