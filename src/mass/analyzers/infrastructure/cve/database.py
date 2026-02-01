"""CVE database.

Stores and manages CVE information for vulnerability matching.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class CVESeverity(str, Enum):
    """CVE severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class CVEEntry:
    """A CVE entry with vulnerability details."""
    cve_id: str
    title: str
    description: str
    severity: CVESeverity
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_packages: list[str] = field(default_factory=list)
    affected_versions: str = ""  # Version constraint string, e.g., ">=1.0.0,<1.5.0"
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_date: datetime | None = None
    cwe_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_critical(self) -> bool:
        return self.severity == CVESeverity.CRITICAL

    @property
    def is_high(self) -> bool:
        return self.severity in (CVESeverity.CRITICAL, CVESeverity.HIGH)


class CVEDatabase:
    """Database of CVE entries for vulnerability matching."""

    def __init__(self):
        """Initialize an empty CVE database."""
        self._entries: dict[str, CVEEntry] = {}
        self._package_index: dict[str, list[str]] = {}  # package -> [cve_ids]

    def add(self, entry: CVEEntry) -> None:
        """Add a CVE entry to the database.

        Args:
            entry: CVE entry to add.
        """
        self._entries[entry.cve_id] = entry

        # Index by package
        for package in entry.affected_packages:
            if package not in self._package_index:
                self._package_index[package] = []
            self._package_index[package].append(entry.cve_id)

    def add_many(self, entries: list[CVEEntry]) -> None:
        """Add multiple CVE entries.

        Args:
            entries: CVE entries to add.
        """
        for entry in entries:
            self.add(entry)

    def get(self, cve_id: str) -> CVEEntry | None:
        """Get a CVE entry by ID.

        Args:
            cve_id: CVE identifier.

        Returns:
            CVE entry or None if not found.
        """
        return self._entries.get(cve_id)

    def get_by_package(self, package: str) -> list[CVEEntry]:
        """Get all CVEs affecting a package.

        Args:
            package: Package name.

        Returns:
            List of CVE entries.
        """
        cve_ids = self._package_index.get(package, [])
        return [self._entries[cve_id] for cve_id in cve_ids]

    def get_critical(self) -> list[CVEEntry]:
        """Get all critical severity CVEs."""
        return [e for e in self._entries.values() if e.is_critical]

    def get_high_and_above(self) -> list[CVEEntry]:
        """Get all high and critical severity CVEs."""
        return [e for e in self._entries.values() if e.is_high]

    def search(
        self,
        query: str | None = None,
        severity: CVESeverity | None = None,
        package: str | None = None,
    ) -> list[CVEEntry]:
        """Search CVE entries.

        Args:
            query: Text search in title/description.
            severity: Filter by severity.
            package: Filter by package.

        Returns:
            Matching CVE entries.
        """
        results = list(self._entries.values())

        if query:
            query_lower = query.lower()
            results = [
                e for e in results
                if query_lower in e.title.lower() or query_lower in e.description.lower()
            ]

        if severity:
            results = [e for e in results if e.severity == severity]

        if package:
            package_cves = set(self._package_index.get(package, []))
            results = [e for e in results if e.cve_id in package_cves]

        return results

    @property
    def count(self) -> int:
        """Total number of CVEs in database."""
        return len(self._entries)

    @property
    def packages(self) -> list[str]:
        """List of all indexed packages."""
        return list(self._package_index.keys())

    def to_dict(self) -> dict[str, Any]:
        """Export database as dictionary."""
        return {
            "cves": [
                {
                    "cve_id": e.cve_id,
                    "title": e.title,
                    "description": e.description,
                    "severity": e.severity.value,
                    "cvss_score": e.cvss_score,
                    "affected_packages": e.affected_packages,
                    "affected_versions": e.affected_versions,
                    "fixed_versions": e.fixed_versions,
                    "references": e.references,
                }
                for e in self._entries.values()
            ]
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CVEDatabase":
        """Create database from dictionary.

        Args:
            data: Dictionary with CVE data.

        Returns:
            CVEDatabase instance.
        """
        db = cls()

        for cve_data in data.get("cves", []):
            entry = CVEEntry(
                cve_id=cve_data["cve_id"],
                title=cve_data["title"],
                description=cve_data["description"],
                severity=CVESeverity(cve_data.get("severity", "unknown")),
                cvss_score=cve_data.get("cvss_score"),
                affected_packages=cve_data.get("affected_packages", []),
                affected_versions=cve_data.get("affected_versions", ""),
                fixed_versions=cve_data.get("fixed_versions", []),
                references=cve_data.get("references", []),
            )
            db.add(entry)

        return db
