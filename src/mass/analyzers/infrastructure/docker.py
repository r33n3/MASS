"""Docker configuration analyzer.

Analyzes Dockerfiles and docker-compose files for security issues.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from mass.core.types import Severity


@dataclass
class DockerFinding:
    """A security finding from Docker analysis."""
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: Path
    line_number: int | None = None
    line_content: str = ""
    remediation: str = ""
    cwe_id: str | None = None


@dataclass
class DockerAnalysisResult:
    """Result of Docker configuration analysis."""
    findings: list[DockerFinding] = field(default_factory=list)
    dockerfiles_analyzed: int = 0
    compose_files_analyzed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def by_severity(self, severity: Severity) -> list[DockerFinding]:
        return [f for f in self.findings if f.severity == severity]


@dataclass
class DockerRule:
    """A security rule for Docker analysis."""
    id: str
    severity: Severity
    title: str
    description: str
    pattern: str
    remediation: str
    file_type: str = "dockerfile"  # dockerfile, compose, or both
    cwe_id: str | None = None
    check_absent: bool = False  # True if pattern absence is the issue


# Dockerfile Security Rules
DOCKERFILE_RULES = [
    DockerRule(
        id="DOCKER001",
        severity=Severity.HIGH,
        title="Running as root",
        description="Container runs as root user by default, which is a security risk.",
        pattern=r"^USER\s+",
        remediation="Add 'USER nonroot' or 'USER 1000' to run as non-root user.",
        check_absent=True,
        cwe_id="CWE-250",
    ),
    DockerRule(
        id="DOCKER002",
        severity=Severity.CRITICAL,
        title="Hardcoded secret in Dockerfile",
        description="Environment variables may contain hardcoded secrets.",
        pattern=r"(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY|APIKEY)\w*\s*=\s*['\"]?[A-Za-z0-9+/=]{8,}['\"]?",
        remediation="Use Docker secrets, environment files, or runtime injection for secrets.",
        cwe_id="CWE-798",
    ),
    DockerRule(
        id="DOCKER003",
        severity=Severity.MEDIUM,
        title="Using latest tag",
        description="Using 'latest' tag makes builds non-reproducible and may introduce vulnerabilities.",
        pattern=r"^FROM\s+\S+:latest\b",
        remediation="Use a specific version tag, e.g., 'python:3.11-slim' instead of 'python:latest'.",
        cwe_id="CWE-1104",
    ),
    DockerRule(
        id="DOCKER004",
        severity=Severity.LOW,
        title="Missing version tag",
        description="Image reference without version tag defaults to 'latest'.",
        pattern=r"^FROM\s+([a-zA-Z0-9._/-]+)(?:\s|$)(?!:)",
        remediation="Specify a version tag for the base image.",
        cwe_id="CWE-1104",
    ),
    DockerRule(
        id="DOCKER005",
        severity=Severity.HIGH,
        title="COPY with --chown root",
        description="Files copied with root ownership may be writable by container processes.",
        pattern=r"COPY\s+--chown=root",
        remediation="Use --chown=nonroot or specific non-root user.",
        cwe_id="CWE-732",
    ),
    DockerRule(
        id="DOCKER006",
        severity=Severity.MEDIUM,
        title="apt-get without --no-install-recommends",
        description="Installing recommended packages increases attack surface.",
        pattern=r"apt-get\s+install(?!.*--no-install-recommends)",
        remediation="Add --no-install-recommends to apt-get install commands.",
        cwe_id="CWE-1188",
    ),
    DockerRule(
        id="DOCKER007",
        severity=Severity.MEDIUM,
        title="Using ADD instead of COPY",
        description="ADD has automatic extraction features that may be unexpected.",
        pattern=r"^ADD\s+",
        remediation="Use COPY unless ADD's auto-extraction feature is specifically needed.",
        cwe_id="CWE-829",
    ),
    DockerRule(
        id="DOCKER008",
        severity=Severity.HIGH,
        title="Exposing SSH port",
        description="SSH access to containers is generally unnecessary and risky.",
        pattern=r"EXPOSE\s+22\b",
        remediation="Remove SSH access; use docker exec for debugging.",
        cwe_id="CWE-284",
    ),
    DockerRule(
        id="DOCKER009",
        severity=Severity.MEDIUM,
        title="Running package manager update and install in separate layers",
        description="Separating update and install can use stale package lists.",
        pattern=r"RUN\s+(?:apt-get|apk|yum)\s+update\s*$",
        remediation="Combine update and install in a single RUN command.",
        cwe_id="CWE-1104",
    ),
    DockerRule(
        id="DOCKER010",
        severity=Severity.HIGH,
        title="Curl piped to shell",
        description="Piping curl output directly to shell is dangerous.",
        pattern=r"curl\s+[^|]*\|\s*(?:sh|bash|zsh)",
        remediation="Download the script first, verify it, then execute.",
        cwe_id="CWE-829",
    ),
    DockerRule(
        id="DOCKER011",
        severity=Severity.HIGH,
        title="Privileged flag in RUN",
        description="Using --privileged gives full host capabilities.",
        pattern=r"--privileged",
        remediation="Avoid --privileged; use specific capabilities if needed.",
        cwe_id="CWE-250",
    ),
    DockerRule(
        id="DOCKER012",
        severity=Severity.MEDIUM,
        title="HEALTHCHECK missing",
        description="No health check defined for the container.",
        pattern=r"^HEALTHCHECK\s+",
        remediation="Add a HEALTHCHECK instruction to monitor container health.",
        check_absent=True,
        cwe_id="CWE-693",
    ),
]

# Docker Compose Security Rules
COMPOSE_RULES = [
    DockerRule(
        id="COMPOSE001",
        severity=Severity.CRITICAL,
        title="Privileged container",
        description="Container is running in privileged mode.",
        pattern=r"privileged:\s*true",
        file_type="compose",
        remediation="Remove privileged: true; use specific capabilities instead.",
        cwe_id="CWE-250",
    ),
    DockerRule(
        id="COMPOSE002",
        severity=Severity.HIGH,
        title="Host network mode",
        description="Container uses host network, bypassing network isolation.",
        pattern=r"network_mode:\s*['\"]?host['\"]?",
        file_type="compose",
        remediation="Use bridge or custom networks for network isolation.",
        cwe_id="CWE-668",
    ),
    DockerRule(
        id="COMPOSE003",
        severity=Severity.HIGH,
        title="Host PID namespace",
        description="Container shares host PID namespace, exposing host processes.",
        pattern=r"pid:\s*['\"]?host['\"]?",
        file_type="compose",
        remediation="Remove pid: host unless specifically required.",
        cwe_id="CWE-668",
    ),
    DockerRule(
        id="COMPOSE004",
        severity=Severity.CRITICAL,
        title="Hardcoded password in compose",
        description="Password is hardcoded in docker-compose file.",
        pattern=r"(?:PASSWORD|PASSWD|PWD)\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*]{6,}['\"]?",
        file_type="compose",
        remediation="Use Docker secrets or environment files for passwords.",
        cwe_id="CWE-798",
    ),
    DockerRule(
        id="COMPOSE005",
        severity=Severity.HIGH,
        title="Docker socket mounted",
        description="Docker socket is mounted, allowing container to control Docker.",
        pattern=r"/var/run/docker\.sock",
        file_type="compose",
        remediation="Avoid mounting Docker socket unless absolutely necessary.",
        cwe_id="CWE-269",
    ),
    DockerRule(
        id="COMPOSE006",
        severity=Severity.MEDIUM,
        title="All capabilities added",
        description="Container has all capabilities added.",
        pattern=r"cap_add:\s*\n\s*-\s*ALL",
        file_type="compose",
        remediation="Add only specific required capabilities.",
        cwe_id="CWE-250",
    ),
    DockerRule(
        id="COMPOSE007",
        severity=Severity.MEDIUM,
        title="No resource limits",
        description="Container has no memory or CPU limits.",
        pattern=r"(?:mem_limit|memory|cpus|cpu_count)",
        file_type="compose",
        remediation="Set memory and CPU limits to prevent resource exhaustion.",
        check_absent=True,
        cwe_id="CWE-770",
    ),
    DockerRule(
        id="COMPOSE008",
        severity=Severity.MEDIUM,
        title="Root filesystem writable",
        description="Container filesystem is writable, increasing attack surface.",
        pattern=r"read_only:\s*true",
        file_type="compose",
        remediation="Set read_only: true and use volumes for writable data.",
        check_absent=True,
        cwe_id="CWE-732",
    ),
    DockerRule(
        id="COMPOSE009",
        severity=Severity.HIGH,
        title="Sensitive port exposed",
        description="Sensitive port exposed to all interfaces.",
        pattern=r"ports:\s*\n(?:\s*-\s*['\"]?(?:0\.0\.0\.0:|)\d+:(?:22|23|3306|5432|27017|6379|9200)\b)",
        file_type="compose",
        remediation="Bind sensitive ports to 127.0.0.1 or use internal networks.",
        cwe_id="CWE-284",
    ),
]


class DockerAnalyzer:
    """Analyzes Docker configuration files for security issues."""

    DOCKERFILE_PATTERNS = [
        "Dockerfile",
        "Dockerfile.*",
        "*.dockerfile",
    ]

    COMPOSE_PATTERNS = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.*.yml",
        "docker-compose.*.yaml",
        "compose.yml",
        "compose.yaml",
    ]

    def __init__(
        self,
        dockerfile_rules: list[DockerRule] | None = None,
        compose_rules: list[DockerRule] | None = None,
    ):
        """Initialize Docker analyzer.

        Args:
            dockerfile_rules: Custom Dockerfile rules. Uses defaults if None.
            compose_rules: Custom compose rules. Uses defaults if None.
        """
        self.dockerfile_rules = dockerfile_rules or DOCKERFILE_RULES
        self.compose_rules = compose_rules or COMPOSE_RULES

    def analyze_dockerfile(self, file_path: Path) -> DockerAnalysisResult:
        """Analyze a Dockerfile.

        Args:
            file_path: Path to the Dockerfile.

        Returns:
            Analysis result with findings.
        """
        result = DockerAnalysisResult(dockerfiles_analyzed=1)

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            result.errors.append(f"Could not read {file_path}: {e}")
            return result

        for finding in self._check_rules(content, self.dockerfile_rules, file_path):
            result.findings.append(finding)

        return result

    def analyze_compose(self, file_path: Path) -> DockerAnalysisResult:
        """Analyze a docker-compose file.

        Args:
            file_path: Path to the compose file.

        Returns:
            Analysis result with findings.
        """
        result = DockerAnalysisResult(compose_files_analyzed=1)

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            result.errors.append(f"Could not read {file_path}: {e}")
            return result

        for finding in self._check_rules(content, self.compose_rules, file_path):
            result.findings.append(finding)

        return result

    def analyze_directory(self, directory: Path) -> DockerAnalysisResult:
        """Analyze all Docker files in a directory.

        Args:
            directory: Directory to scan.

        Returns:
            Combined analysis result.
        """
        result = DockerAnalysisResult()

        # Find and analyze Dockerfiles
        for dockerfile in self._find_dockerfiles(directory):
            file_result = self.analyze_dockerfile(dockerfile)
            result.findings.extend(file_result.findings)
            result.dockerfiles_analyzed += file_result.dockerfiles_analyzed
            result.errors.extend(file_result.errors)

        # Find and analyze compose files
        for compose_file in self._find_compose_files(directory):
            file_result = self.analyze_compose(compose_file)
            result.findings.extend(file_result.findings)
            result.compose_files_analyzed += file_result.compose_files_analyzed
            result.errors.extend(file_result.errors)

        return result

    def _check_rules(
        self,
        content: str,
        rules: list[DockerRule],
        file_path: Path,
    ) -> Iterator[DockerFinding]:
        """Check content against rules.

        Args:
            content: File content.
            rules: Rules to check.
            file_path: Path to the file.

        Yields:
            DockerFinding for each rule violation.
        """
        lines = content.splitlines()

        for rule in rules:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)

            if rule.check_absent:
                # Check if pattern is absent (a required thing is missing)
                if not pattern.search(content):
                    yield DockerFinding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        file_path=file_path,
                        remediation=rule.remediation,
                        cwe_id=rule.cwe_id,
                    )
            else:
                # Check for pattern presence (something bad is present)
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                    yield DockerFinding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_content.strip(),
                        remediation=rule.remediation,
                        cwe_id=rule.cwe_id,
                    )

    def _find_dockerfiles(self, directory: Path) -> Iterator[Path]:
        """Find Dockerfiles in directory."""
        for pattern in self.DOCKERFILE_PATTERNS:
            if "*" in pattern:
                yield from directory.rglob(pattern)
            else:
                dockerfile = directory / pattern
                if dockerfile.exists():
                    yield dockerfile

    def _find_compose_files(self, directory: Path) -> Iterator[Path]:
        """Find compose files in directory."""
        for pattern in self.COMPOSE_PATTERNS:
            if "*" in pattern:
                yield from directory.rglob(pattern)
            else:
                compose_file = directory / pattern
                if compose_file.exists():
                    yield compose_file
