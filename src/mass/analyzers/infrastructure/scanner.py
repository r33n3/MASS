"""Infrastructure scanner.

Main scanner that combines Docker, Kubernetes, Terraform, and CVE analysis.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mass.core.types import Severity
from mass.analyzers.infrastructure.docker import DockerAnalyzer, DockerAnalysisResult
from mass.analyzers.infrastructure.kubernetes import KubernetesAnalyzer, K8sAnalysisResult
from mass.analyzers.infrastructure.terraform import TerraformAnalyzer, TerraformAnalysisResult
from mass.analyzers.infrastructure.cve import (
    CVEDatabase,
    CVEMatcher,
    MatchResult,
    get_ai_framework_database,
)

logger = logging.getLogger(__name__)


@dataclass
class InfrastructureFinding:
    """A finding from infrastructure analysis."""
    source: str  # docker, kubernetes, terraform, cve
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: Path | None = None
    line_number: int | None = None
    resource_type: str = ""
    resource_name: str = ""
    remediation: str = ""
    cwe_id: str | None = None


@dataclass
class InfrastructureScanResult:
    """Result of infrastructure scanning."""
    findings: list[InfrastructureFinding] = field(default_factory=list)

    # Component results
    docker_result: DockerAnalysisResult | None = None
    kubernetes_result: K8sAnalysisResult | None = None
    terraform_result: TerraformAnalysisResult | None = None
    cve_matches: list[MatchResult] = field(default_factory=list)

    # Stats
    files_scanned: int = 0
    resources_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def by_severity(self, severity: Severity) -> list[InfrastructureFinding]:
        return [f for f in self.findings if f.severity == severity]

    def by_source(self, source: str) -> list[InfrastructureFinding]:
        return [f for f in self.findings if f.source == source]


class InfrastructureScanner:
    """Scans infrastructure configurations for security issues.

    Combines analysis of:
    - Docker configurations (Dockerfile, docker-compose)
    - Kubernetes manifests
    - Terraform configurations
    - Dependency CVE matching
    """

    def __init__(
        self,
        docker_analyzer: DockerAnalyzer | None = None,
        kubernetes_analyzer: KubernetesAnalyzer | None = None,
        terraform_analyzer: TerraformAnalyzer | None = None,
        cve_database: CVEDatabase | None = None,
    ):
        """Initialize infrastructure scanner.

        Args:
            docker_analyzer: Custom Docker analyzer.
            kubernetes_analyzer: Custom Kubernetes analyzer.
            terraform_analyzer: Custom Terraform analyzer.
            cve_database: Custom CVE database.
        """
        self.docker_analyzer = docker_analyzer or DockerAnalyzer()
        self.kubernetes_analyzer = kubernetes_analyzer or KubernetesAnalyzer()
        self.terraform_analyzer = terraform_analyzer or TerraformAnalyzer()
        self.cve_database = cve_database or get_ai_framework_database()
        self.cve_matcher = CVEMatcher(self.cve_database)

    def scan(
        self,
        path: str | Path,
        include_docker: bool = True,
        include_kubernetes: bool = True,
        include_terraform: bool = True,
        include_cve: bool = True,
        dependencies: dict[str, str] | None = None,
    ) -> InfrastructureScanResult:
        """Scan a directory for infrastructure security issues.

        Args:
            path: Directory to scan.
            include_docker: Scan Docker configurations.
            include_kubernetes: Scan Kubernetes manifests.
            include_terraform: Scan Terraform configurations.
            include_cve: Check for CVEs in dependencies.
            dependencies: Package dependencies to check (name -> version).

        Returns:
            Scan result with all findings.
        """
        path = Path(path)
        result = InfrastructureScanResult()

        if not path.exists():
            result.errors.append(f"Path does not exist: {path}")
            return result

        if not path.is_dir():
            result.errors.append(f"Path is not a directory: {path}")
            return result

        logger.info(f"Scanning infrastructure at: {path}")

        # Docker analysis
        if include_docker:
            self._scan_docker(path, result)

        # Kubernetes analysis
        if include_kubernetes:
            self._scan_kubernetes(path, result)

        # Terraform analysis
        if include_terraform:
            self._scan_terraform(path, result)

        # CVE matching
        if include_cve and dependencies:
            self._check_cves(dependencies, result)

        logger.info(
            f"Infrastructure scan complete: {len(result.findings)} findings, "
            f"{result.files_scanned} files scanned"
        )

        return result

    def _scan_docker(self, path: Path, result: InfrastructureScanResult) -> None:
        """Scan Docker configurations."""
        try:
            docker_result = self.docker_analyzer.analyze_directory(path)
            result.docker_result = docker_result

            result.files_scanned += (
                docker_result.dockerfiles_analyzed +
                docker_result.compose_files_analyzed
            )
            result.errors.extend(docker_result.errors)

            # Convert Docker findings to infrastructure findings
            for finding in docker_result.findings:
                result.findings.append(InfrastructureFinding(
                    source="docker",
                    rule_id=finding.rule_id,
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    remediation=finding.remediation,
                    cwe_id=finding.cwe_id,
                ))
        except Exception as e:
            logger.error(f"Docker analysis error: {e}")
            result.errors.append(f"Docker analysis error: {e}")

    def _scan_kubernetes(self, path: Path, result: InfrastructureScanResult) -> None:
        """Scan Kubernetes manifests."""
        try:
            k8s_result = self.kubernetes_analyzer.analyze_directory(path)
            result.kubernetes_result = k8s_result

            result.files_scanned += k8s_result.manifests_analyzed
            result.resources_scanned += k8s_result.resources_analyzed
            result.errors.extend(k8s_result.errors)

            # Convert K8s findings to infrastructure findings
            for finding in k8s_result.findings:
                result.findings.append(InfrastructureFinding(
                    source="kubernetes",
                    rule_id=finding.rule_id,
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    file_path=finding.file_path,
                    resource_type=finding.resource_kind,
                    resource_name=finding.resource_name,
                    remediation=finding.remediation,
                    cwe_id=finding.cwe_id,
                ))
        except Exception as e:
            logger.error(f"Kubernetes analysis error: {e}")
            result.errors.append(f"Kubernetes analysis error: {e}")

    def _scan_terraform(self, path: Path, result: InfrastructureScanResult) -> None:
        """Scan Terraform configurations."""
        try:
            tf_result = self.terraform_analyzer.analyze_directory(path)
            result.terraform_result = tf_result

            result.files_scanned += tf_result.files_analyzed
            result.resources_scanned += tf_result.resources_analyzed
            result.errors.extend(tf_result.errors)

            # Convert Terraform findings to infrastructure findings
            for finding in tf_result.findings:
                result.findings.append(InfrastructureFinding(
                    source="terraform",
                    rule_id=finding.rule_id,
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    resource_type=finding.resource_type,
                    resource_name=finding.resource_name,
                    remediation=finding.remediation,
                    cwe_id=finding.cwe_id,
                ))
        except Exception as e:
            logger.error(f"Terraform analysis error: {e}")
            result.errors.append(f"Terraform analysis error: {e}")

    def _check_cves(
        self,
        dependencies: dict[str, str],
        result: InfrastructureScanResult,
    ) -> None:
        """Check dependencies for CVEs."""
        try:
            matches = self.cve_matcher.check_requirements(dependencies)
            result.cve_matches = matches

            # Convert CVE matches to infrastructure findings
            for match in matches:
                if not match.is_vulnerable:
                    continue

                cve = match.cve
                result.findings.append(InfrastructureFinding(
                    source="cve",
                    rule_id=cve.cve_id,
                    severity=Severity(cve.severity.value),
                    title=cve.title,
                    description=f"{match.package}=={match.version}: {cve.description}",
                    resource_type="dependency",
                    resource_name=match.package,
                    remediation=f"Upgrade to {', '.join(cve.fixed_versions)}" if cve.fixed_versions else "Update to latest version",
                    cwe_id=cve.cwe_ids[0] if cve.cwe_ids else None,
                ))
        except Exception as e:
            logger.error(f"CVE check error: {e}")
            result.errors.append(f"CVE check error: {e}")

    def get_summary(self, result: InfrastructureScanResult) -> dict[str, Any]:
        """Get a summary of the scan results.

        Args:
            result: Scan result.

        Returns:
            Summary dictionary.
        """
        findings_by_source = {}
        for source in ["docker", "kubernetes", "terraform", "cve"]:
            source_findings = result.by_source(source)
            findings_by_source[source] = {
                "total": len(source_findings),
                "critical": sum(1 for f in source_findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in source_findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in source_findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in source_findings if f.severity == Severity.LOW),
            }

        return {
            "total_findings": len(result.findings),
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "files_scanned": result.files_scanned,
            "resources_scanned": result.resources_scanned,
            "findings_by_source": findings_by_source,
            "error_count": len(result.errors),
        }
