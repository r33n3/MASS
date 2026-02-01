"""CVE database module.

Provides CVE database for AI frameworks and version matching.
"""

from mass.analyzers.infrastructure.cve.database import CVEDatabase, CVEEntry, CVESeverity
from mass.analyzers.infrastructure.cve.matcher import CVEMatcher, MatchResult
from mass.analyzers.infrastructure.cve.frameworks import AI_FRAMEWORK_CVES, get_ai_framework_database

__all__ = [
    "CVEDatabase",
    "CVEEntry",
    "CVESeverity",
    "CVEMatcher",
    "MatchResult",
    "AI_FRAMEWORK_CVES",
    "get_ai_framework_database",
]
