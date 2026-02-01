"""CVE version matcher.

Matches installed package versions against CVE vulnerability ranges.
"""

import re
from dataclasses import dataclass
from typing import Tuple

from mass.analyzers.infrastructure.cve.database import CVEDatabase, CVEEntry


@dataclass
class MatchResult:
    """Result of CVE matching."""
    package: str
    version: str
    cve: CVEEntry
    is_vulnerable: bool
    message: str


class CVEMatcher:
    """Matches package versions against CVE database."""

    def __init__(self, database: CVEDatabase):
        """Initialize CVE matcher.

        Args:
            database: CVE database to match against.
        """
        self.database = database

    def check_package(self, package: str, version: str) -> list[MatchResult]:
        """Check a package version for vulnerabilities.

        Args:
            package: Package name.
            version: Installed version.

        Returns:
            List of matching CVE results.
        """
        results = []
        cves = self.database.get_by_package(package)

        for cve in cves:
            is_vulnerable = self._version_in_range(version, cve.affected_versions)

            if is_vulnerable:
                results.append(MatchResult(
                    package=package,
                    version=version,
                    cve=cve,
                    is_vulnerable=True,
                    message=f"{package}=={version} is vulnerable to {cve.cve_id}: {cve.title}",
                ))

        return results

    def check_requirements(
        self,
        requirements: dict[str, str],
    ) -> list[MatchResult]:
        """Check a requirements dict for vulnerabilities.

        Args:
            requirements: Dict of package -> version.

        Returns:
            List of all matching CVE results.
        """
        results = []

        for package, version in requirements.items():
            results.extend(self.check_package(package, version))

        return results

    def _version_in_range(self, version: str, version_spec: str) -> bool:
        """Check if a version is within a vulnerability range.

        Args:
            version: Actual version string.
            version_spec: Version specification (e.g., ">=1.0.0,<2.0.0").

        Returns:
            True if version is within the vulnerable range.
        """
        if not version_spec:
            return True  # No spec means all versions affected

        try:
            parsed_version = self._parse_version(version)
        except ValueError:
            return False

        # Parse version constraints
        constraints = self._parse_version_spec(version_spec)

        for op, spec_version in constraints:
            try:
                parsed_spec = self._parse_version(spec_version)
            except ValueError:
                continue

            if not self._compare_versions(parsed_version, op, parsed_spec):
                return False

        return True

    def _parse_version(self, version: str) -> Tuple[int, ...]:
        """Parse a version string into a tuple of integers.

        Args:
            version: Version string (e.g., "1.2.3").

        Returns:
            Tuple of version components.
        """
        # Clean up version string
        version = version.strip().lstrip("v")

        # Handle pre-release versions (e.g., 1.0.0a1, 1.0.0-beta)
        version = re.split(r"[-+a-zA-Z]", version)[0]

        parts = version.split(".")
        result = []

        for part in parts:
            # Extract numeric part
            match = re.match(r"(\d+)", part)
            if match:
                result.append(int(match.group(1)))
            else:
                result.append(0)

        # Pad to at least 3 components
        while len(result) < 3:
            result.append(0)

        return tuple(result)

    def _parse_version_spec(self, spec: str) -> list[Tuple[str, str]]:
        """Parse a version specification into constraints.

        Args:
            spec: Version specification (e.g., ">=1.0.0,<2.0.0").

        Returns:
            List of (operator, version) tuples.
        """
        constraints = []

        # Split by comma
        parts = spec.split(",")

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Match operator and version
            match = re.match(r"(>=|<=|>|<|==|!=|~=)?\s*(.+)", part)
            if match:
                op = match.group(1) or "=="
                version = match.group(2).strip()
                constraints.append((op, version))

        return constraints

    def _compare_versions(
        self,
        version: Tuple[int, ...],
        op: str,
        spec_version: Tuple[int, ...],
    ) -> bool:
        """Compare two version tuples.

        Args:
            version: Actual version.
            op: Comparison operator.
            spec_version: Specification version.

        Returns:
            True if comparison passes.
        """
        if op == ">=":
            return version >= spec_version
        elif op == "<=":
            return version <= spec_version
        elif op == ">":
            return version > spec_version
        elif op == "<":
            return version < spec_version
        elif op == "==":
            return version == spec_version
        elif op == "!=":
            return version != spec_version
        elif op == "~=":
            # Compatible release: ~=1.2 means >=1.2,<2.0
            major = spec_version[0]
            return version >= spec_version and version < (major + 1, 0, 0)

        return False


def check_vulnerabilities(
    requirements: dict[str, str],
    database: CVEDatabase,
) -> list[MatchResult]:
    """Convenience function to check requirements for vulnerabilities.

    Args:
        requirements: Dict of package -> version.
        database: CVE database.

    Returns:
        List of vulnerability matches.
    """
    matcher = CVEMatcher(database)
    return matcher.check_requirements(requirements)
