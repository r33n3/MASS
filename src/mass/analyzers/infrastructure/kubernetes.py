"""Kubernetes configuration analyzer.

Analyzes Kubernetes manifests for security issues.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

from mass.core.types import Severity


@dataclass
class K8sFinding:
    """A security finding from Kubernetes analysis."""
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: Path
    resource_kind: str
    resource_name: str
    namespace: str | None = None
    remediation: str = ""
    cwe_id: str | None = None
    path: str = ""


@dataclass
class K8sAnalysisResult:
    """Result of Kubernetes manifest analysis."""
    findings: list[K8sFinding] = field(default_factory=list)
    manifests_analyzed: int = 0
    resources_analyzed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def by_severity(self, severity: Severity) -> list[K8sFinding]:
        return [f for f in self.findings if f.severity == severity]


@dataclass
class K8sRule:
    """A security rule for Kubernetes analysis."""
    id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    kinds: list[str]  # Resource kinds this applies to
    check_func: str  # Name of the check function
    cwe_id: str | None = None


# Kubernetes Security Rules
K8S_RULES = [
    K8sRule(
        id="K8S001",
        severity=Severity.CRITICAL,
        title="Container running as root",
        description="Container is configured to run as root user.",
        remediation="Set securityContext.runAsNonRoot: true",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_run_as_root",
        cwe_id="CWE-250",
    ),
    K8sRule(
        id="K8S002",
        severity=Severity.HIGH,
        title="Privileged container",
        description="Container is running in privileged mode.",
        remediation="Set securityContext.privileged: false",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_privileged",
        cwe_id="CWE-250",
    ),
    K8sRule(
        id="K8S003",
        severity=Severity.HIGH,
        title="Host network enabled",
        description="Pod uses host network namespace.",
        remediation="Set hostNetwork: false unless specifically required",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_host_network",
        cwe_id="CWE-668",
    ),
    K8sRule(
        id="K8S004",
        severity=Severity.HIGH,
        title="Host PID enabled",
        description="Pod shares host PID namespace.",
        remediation="Set hostPID: false unless specifically required",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_host_pid",
        cwe_id="CWE-668",
    ),
    K8sRule(
        id="K8S005",
        severity=Severity.HIGH,
        title="Host IPC enabled",
        description="Pod shares host IPC namespace.",
        remediation="Set hostIPC: false unless specifically required",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_host_ipc",
        cwe_id="CWE-668",
    ),
    K8sRule(
        id="K8S006",
        severity=Severity.MEDIUM,
        title="No resource limits",
        description="Container has no resource limits set.",
        remediation="Set resources.limits for CPU and memory",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_resource_limits",
        cwe_id="CWE-770",
    ),
    K8sRule(
        id="K8S007",
        severity=Severity.MEDIUM,
        title="Writable root filesystem",
        description="Container filesystem is writable.",
        remediation="Set securityContext.readOnlyRootFilesystem: true",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_readonly_fs",
        cwe_id="CWE-732",
    ),
    K8sRule(
        id="K8S008",
        severity=Severity.HIGH,
        title="Dangerous capabilities",
        description="Container has dangerous Linux capabilities.",
        remediation="Remove dangerous capabilities; use minimal required set",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_capabilities",
        cwe_id="CWE-250",
    ),
    K8sRule(
        id="K8S009",
        severity=Severity.CRITICAL,
        title="Secrets in environment variables",
        description="Secrets are mounted as environment variables instead of volumes.",
        remediation="Mount secrets as files instead of environment variables",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_secrets_in_env",
        cwe_id="CWE-522",
    ),
    K8sRule(
        id="K8S010",
        severity=Severity.HIGH,
        title="Default service account",
        description="Pod uses default service account.",
        remediation="Create and use a dedicated service account",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_service_account",
        cwe_id="CWE-284",
    ),
    K8sRule(
        id="K8S011",
        severity=Severity.HIGH,
        title="Auto-mounted service account token",
        description="Service account token is auto-mounted.",
        remediation="Set automountServiceAccountToken: false if not needed",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_automount_token",
        cwe_id="CWE-522",
    ),
    K8sRule(
        id="K8S012",
        severity=Severity.MEDIUM,
        title="Missing network policy",
        description="No NetworkPolicy restricts traffic to this namespace.",
        remediation="Create NetworkPolicy to restrict ingress/egress",
        kinds=["Namespace"],
        check_func="check_network_policy",
        cwe_id="CWE-284",
    ),
    K8sRule(
        id="K8S013",
        severity=Severity.HIGH,
        title="RBAC cluster-admin binding",
        description="ClusterRoleBinding grants cluster-admin privileges.",
        remediation="Use minimal required permissions instead of cluster-admin",
        kinds=["ClusterRoleBinding", "RoleBinding"],
        check_func="check_cluster_admin",
        cwe_id="CWE-269",
    ),
    K8sRule(
        id="K8S014",
        severity=Severity.MEDIUM,
        title="Missing liveness probe",
        description="Container has no liveness probe defined.",
        remediation="Add livenessProbe to detect and restart unhealthy containers",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet"],
        check_func="check_liveness_probe",
        cwe_id="CWE-693",
    ),
    K8sRule(
        id="K8S015",
        severity=Severity.LOW,
        title="Using latest image tag",
        description="Container uses 'latest' or no image tag.",
        remediation="Use specific image tags for reproducibility",
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"],
        check_func="check_image_tag",
        cwe_id="CWE-1104",
    ),
]

# Dangerous Linux capabilities
DANGEROUS_CAPABILITIES = {
    "CAP_SYS_ADMIN",
    "CAP_NET_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_BOOT",
    "CAP_SYS_TIME",
    "CAP_NET_RAW",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "ALL",
}


class KubernetesAnalyzer:
    """Analyzes Kubernetes manifests for security issues."""

    MANIFEST_PATTERNS = [
        "*.yaml",
        "*.yml",
    ]

    def __init__(self, rules: list[K8sRule] | None = None):
        """Initialize Kubernetes analyzer.

        Args:
            rules: Custom rules. Uses defaults if None.
        """
        self.rules = rules or K8S_RULES

    def analyze_manifest(self, file_path: Path) -> K8sAnalysisResult:
        """Analyze a Kubernetes manifest file.

        Args:
            file_path: Path to the manifest file.

        Returns:
            Analysis result with findings.
        """
        result = K8sAnalysisResult(manifests_analyzed=1)

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            result.errors.append(f"Could not read {file_path}: {e}")
            return result

        # Parse all YAML documents in the file
        try:
            documents = list(yaml.safe_load_all(content))
        except yaml.YAMLError as e:
            result.errors.append(f"YAML parse error in {file_path}: {e}")
            return result

        for doc in documents:
            if not doc or not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            if not kind:
                continue

            result.resources_analyzed += 1

            for finding in self._check_resource(doc, file_path):
                result.findings.append(finding)

        return result

    def analyze_directory(self, directory: Path) -> K8sAnalysisResult:
        """Analyze all Kubernetes manifests in a directory.

        Args:
            directory: Directory to scan.

        Returns:
            Combined analysis result.
        """
        result = K8sAnalysisResult()

        for manifest_path in self._find_manifests(directory):
            # Skip non-K8s YAML files
            if not self._is_k8s_manifest(manifest_path):
                continue

            file_result = self.analyze_manifest(manifest_path)
            result.findings.extend(file_result.findings)
            result.manifests_analyzed += file_result.manifests_analyzed
            result.resources_analyzed += file_result.resources_analyzed
            result.errors.extend(file_result.errors)

        return result

    def _check_resource(
        self,
        resource: dict[str, Any],
        file_path: Path,
    ) -> Iterator[K8sFinding]:
        """Check a resource against all applicable rules.

        Args:
            resource: Kubernetes resource.
            file_path: Source file path.

        Yields:
            K8sFinding for each rule violation.
        """
        kind = resource.get("kind", "")
        metadata = resource.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace")

        for rule in self.rules:
            if kind not in rule.kinds:
                continue

            check_method = getattr(self, f"_{rule.check_func}", None)
            if not check_method:
                continue

            if check_method(resource):
                yield K8sFinding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    file_path=file_path,
                    resource_kind=kind,
                    resource_name=name,
                    namespace=namespace,
                    remediation=rule.remediation,
                    cwe_id=rule.cwe_id,
                )

    def _get_pod_spec(self, resource: dict[str, Any]) -> dict[str, Any] | None:
        """Extract pod spec from various resource types."""
        kind = resource.get("kind", "")

        if kind == "Pod":
            return resource.get("spec", {})
        elif kind in ("Deployment", "DaemonSet", "StatefulSet", "Job"):
            return resource.get("spec", {}).get("template", {}).get("spec", {})
        elif kind == "CronJob":
            return (
                resource.get("spec", {})
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        return None

    def _get_containers(self, resource: dict[str, Any]) -> list[dict[str, Any]]:
        """Get all containers from a resource."""
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return []

        containers = pod_spec.get("containers", [])
        init_containers = pod_spec.get("initContainers", [])
        return containers + init_containers

    # Check functions for each rule

    def _check_run_as_root(self, resource: dict[str, Any]) -> bool:
        """Check if container runs as root."""
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return False

        # Check pod-level security context
        pod_sc = pod_spec.get("securityContext", {})
        if pod_sc.get("runAsNonRoot") is True:
            return False

        # Check container-level security context
        for container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            if sc.get("runAsNonRoot") is True:
                continue
            if sc.get("runAsUser", 0) == 0:
                return True
            if "runAsUser" not in sc and not pod_sc.get("runAsNonRoot"):
                return True

        return False

    def _check_privileged(self, resource: dict[str, Any]) -> bool:
        """Check if container is privileged."""
        for container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            if sc.get("privileged") is True:
                return True
        return False

    def _check_host_network(self, resource: dict[str, Any]) -> bool:
        """Check if pod uses host network."""
        pod_spec = self._get_pod_spec(resource)
        return pod_spec.get("hostNetwork") is True if pod_spec else False

    def _check_host_pid(self, resource: dict[str, Any]) -> bool:
        """Check if pod uses host PID namespace."""
        pod_spec = self._get_pod_spec(resource)
        return pod_spec.get("hostPID") is True if pod_spec else False

    def _check_host_ipc(self, resource: dict[str, Any]) -> bool:
        """Check if pod uses host IPC namespace."""
        pod_spec = self._get_pod_spec(resource)
        return pod_spec.get("hostIPC") is True if pod_spec else False

    def _check_resource_limits(self, resource: dict[str, Any]) -> bool:
        """Check if container has resource limits."""
        for container in self._get_containers(resource):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("memory") or not limits.get("cpu"):
                return True
        return False

    def _check_readonly_fs(self, resource: dict[str, Any]) -> bool:
        """Check if container filesystem is read-only."""
        for container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            if not sc.get("readOnlyRootFilesystem"):
                return True
        return False

    def _check_capabilities(self, resource: dict[str, Any]) -> bool:
        """Check for dangerous capabilities."""
        for container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            capabilities = sc.get("capabilities", {})
            add_caps = set(capabilities.get("add", []))
            if add_caps & DANGEROUS_CAPABILITIES:
                return True
        return False

    def _check_secrets_in_env(self, resource: dict[str, Any]) -> bool:
        """Check if secrets are used as environment variables."""
        for container in self._get_containers(resource):
            env = container.get("env", [])
            for env_var in env:
                value_from = env_var.get("valueFrom", {})
                if value_from.get("secretKeyRef"):
                    return True

            env_from = container.get("envFrom", [])
            for env_source in env_from:
                if env_source.get("secretRef"):
                    return True
        return False

    def _check_service_account(self, resource: dict[str, Any]) -> bool:
        """Check if pod uses default service account."""
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return False

        sa = pod_spec.get("serviceAccountName", "default")
        return sa == "default"

    def _check_automount_token(self, resource: dict[str, Any]) -> bool:
        """Check if service account token is auto-mounted."""
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return False

        # Default is true if not specified
        return pod_spec.get("automountServiceAccountToken", True)

    def _check_network_policy(self, resource: dict[str, Any]) -> bool:
        """Check for network policy (only for Namespace kind)."""
        # This is a simplified check - in reality you'd need to
        # check if any NetworkPolicy exists for the namespace
        return True  # Flag for manual review

    def _check_cluster_admin(self, resource: dict[str, Any]) -> bool:
        """Check if binding grants cluster-admin."""
        role_ref = resource.get("roleRef", {})
        return role_ref.get("name") == "cluster-admin"

    def _check_liveness_probe(self, resource: dict[str, Any]) -> bool:
        """Check if container has liveness probe."""
        for container in self._get_containers(resource):
            if not container.get("livenessProbe"):
                return True
        return False

    def _check_image_tag(self, resource: dict[str, Any]) -> bool:
        """Check if container uses latest or no image tag."""
        for container in self._get_containers(resource):
            image = container.get("image", "")
            # Check for :latest or no tag
            if image.endswith(":latest") or ":" not in image.split("/")[-1]:
                return True
        return False

    def _find_manifests(self, directory: Path) -> Iterator[Path]:
        """Find YAML files in directory."""
        for pattern in self.MANIFEST_PATTERNS:
            yield from directory.rglob(pattern)

    def _is_k8s_manifest(self, file_path: Path) -> bool:
        """Check if a YAML file is a Kubernetes manifest."""
        try:
            content = file_path.read_text(encoding="utf-8")
            # Simple heuristic: check for apiVersion and kind
            return "apiVersion:" in content and "kind:" in content
        except Exception:
            return False
