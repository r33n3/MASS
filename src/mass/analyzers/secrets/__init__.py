"""Secret detection module.

Detects exposed secrets, credentials, and API keys in code and configuration.
"""

from mass.analyzers.secrets.detector import SecretDetector
from mass.analyzers.secrets.patterns import SecretPattern, SECRET_PATTERNS
from mass.analyzers.secrets.entropy import EntropyAnalyzer
from mass.analyzers.secrets.validators import SecretValidator

__all__ = [
    "SecretDetector",
    "SecretPattern",
    "SECRET_PATTERNS",
    "EntropyAnalyzer",
    "SecretValidator",
]
