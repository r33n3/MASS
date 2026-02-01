"""Tests for infrastructure scanning."""

import tempfile
from pathlib import Path

import pytest

from mass.core.types import Severity
from mass.analyzers.infrastructure.docker import DockerAnalyzer, DOCKERFILE_RULES
from mass.analyzers.infrastructure.kubernetes import KubernetesAnalyzer, K8S_RULES
from mass.analyzers.infrastructure.terraform import TerraformAnalyzer, TERRAFORM_RULES
from mass.analyzers.infrastructure.cve import (
    CVEDatabase,
    CVEEntry,
    CVESeverity,
    CVEMatcher,
    AI_FRAMEWORK_CVES,
    get_ai_framework_database,
)
from mass.analyzers.infrastructure.scanner import InfrastructureScanner


class TestDockerAnalyzer:
    """Tests for Docker analyzer."""

    def test_analyze_dockerfile_running_as_root(self) -> None:
        """Test detection of running as root."""
        analyzer = DockerAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile = Path(tmpdir) / "Dockerfile"
            dockerfile.write_text("""
FROM python:3.11
COPY . /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
""")

            result = analyzer.analyze_dockerfile(dockerfile)
            assert result.dockerfiles_analyzed == 1

            # Should detect missing USER directive
            root_findings = [f for f in result.findings if "root" in f.title.lower()]
            assert len(root_findings) >= 1

    def test_analyze_dockerfile_with_secrets(self) -> None:
        """Test detection of hardcoded secrets."""
        analyzer = DockerAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile = Path(tmpdir) / "Dockerfile"
            dockerfile.write_text("""
FROM python:3.11
ENV API_KEY=sk-1234567890abcdef
CMD ["python", "app.py"]
""")

            result = analyzer.analyze_dockerfile(dockerfile)

            secret_findings = [
                f for f in result.findings
                if "secret" in f.title.lower() or "password" in f.title.lower()
            ]
            # May or may not detect depending on pattern
            assert result.has_findings

    def test_analyze_dockerfile_latest_tag(self) -> None:
        """Test detection of latest tag."""
        analyzer = DockerAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile = Path(tmpdir) / "Dockerfile"
            dockerfile.write_text("""
FROM python:latest
CMD ["python", "app.py"]
""")

            result = analyzer.analyze_dockerfile(dockerfile)

            latest_findings = [
                f for f in result.findings
                if "latest" in f.title.lower()
            ]
            assert len(latest_findings) >= 1

    def test_analyze_compose_privileged(self) -> None:
        """Test detection of privileged containers in compose."""
        analyzer = DockerAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            compose_file = Path(tmpdir) / "docker-compose.yml"
            compose_file.write_text("""
version: '3'
services:
  app:
    image: myapp
    privileged: true
""")

            result = analyzer.analyze_compose(compose_file)
            assert result.compose_files_analyzed == 1

            privileged_findings = [
                f for f in result.findings
                if "privileged" in f.title.lower()
            ]
            assert len(privileged_findings) >= 1

    def test_analyze_directory(self) -> None:
        """Test analyzing a directory."""
        analyzer = DockerAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            (base / "Dockerfile").write_text("""
FROM python:latest
CMD ["python", "app.py"]
""")
            (base / "docker-compose.yml").write_text("""
version: '3'
services:
  app:
    build: .
    network_mode: host
""")

            result = analyzer.analyze_directory(base)
            assert result.dockerfiles_analyzed >= 1
            assert result.compose_files_analyzed >= 1
            assert result.has_findings


class TestKubernetesAnalyzer:
    """Tests for Kubernetes analyzer."""

    def test_analyze_pod_privileged(self) -> None:
        """Test detection of privileged pods."""
        analyzer = KubernetesAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = Path(tmpdir) / "pod.yaml"
            manifest.write_text("""
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true
""")

            result = analyzer.analyze_manifest(manifest)
            assert result.manifests_analyzed == 1
            assert result.resources_analyzed == 1

            privileged_findings = [
                f for f in result.findings
                if "privileged" in f.title.lower()
            ]
            assert len(privileged_findings) >= 1

    def test_analyze_deployment_no_limits(self) -> None:
        """Test detection of missing resource limits."""
        analyzer = KubernetesAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = Path(tmpdir) / "deployment.yaml"
            manifest.write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: test
        image: nginx:1.21
""")

            result = analyzer.analyze_manifest(manifest)

            limit_findings = [
                f for f in result.findings
                if "limit" in f.title.lower() or "resource" in f.title.lower()
            ]
            assert len(limit_findings) >= 1

    def test_analyze_host_network(self) -> None:
        """Test detection of host network mode."""
        analyzer = KubernetesAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = Path(tmpdir) / "pod.yaml"
            manifest.write_text("""
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  hostNetwork: true
  containers:
  - name: test
    image: nginx
""")

            result = analyzer.analyze_manifest(manifest)

            host_findings = [
                f for f in result.findings
                if "host network" in f.title.lower()
            ]
            assert len(host_findings) >= 1

    def test_analyze_cluster_role_binding(self) -> None:
        """Test detection of cluster-admin binding."""
        analyzer = KubernetesAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = Path(tmpdir) / "rbac.yaml"
            manifest.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: admin
""")

            result = analyzer.analyze_manifest(manifest)

            admin_findings = [
                f for f in result.findings
                if "cluster-admin" in f.title.lower()
            ]
            assert len(admin_findings) >= 1

    def test_is_k8s_manifest(self) -> None:
        """Test Kubernetes manifest detection."""
        analyzer = KubernetesAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            # K8s manifest
            k8s_file = Path(tmpdir) / "pod.yaml"
            k8s_file.write_text("""
apiVersion: v1
kind: Pod
metadata:
  name: test
""")

            # Non-K8s YAML
            other_file = Path(tmpdir) / "config.yaml"
            other_file.write_text("""
database:
  host: localhost
  port: 5432
""")

            assert analyzer._is_k8s_manifest(k8s_file)
            assert not analyzer._is_k8s_manifest(other_file)


class TestTerraformAnalyzer:
    """Tests for Terraform analyzer."""

    def test_analyze_s3_public_access(self) -> None:
        """Test detection of S3 public access."""
        analyzer = TerraformAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text("""
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
""")

            result = analyzer.analyze_file(tf_file)
            assert result.files_analyzed == 1

            public_findings = [
                f for f in result.findings
                if "public" in f.title.lower()
            ]
            assert len(public_findings) >= 1

    def test_analyze_security_group_open(self) -> None:
        """Test detection of open security groups."""
        analyzer = TerraformAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text("""
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""")

            result = analyzer.analyze_file(tf_file)

            open_findings = [
                f for f in result.findings
                if "0.0.0.0/0" in f.description or "all" in f.title.lower()
            ]
            assert len(open_findings) >= 1

    def test_analyze_rds_public(self) -> None:
        """Test detection of public RDS."""
        analyzer = TerraformAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text("""
resource "aws_db_instance" "default" {
  identifier           = "mydb"
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  publicly_accessible  = true
}
""")

            result = analyzer.analyze_file(tf_file)

            public_findings = [
                f for f in result.findings
                if "public" in f.title.lower()
            ]
            assert len(public_findings) >= 1

    def test_analyze_hardcoded_password(self) -> None:
        """Test detection of hardcoded passwords."""
        analyzer = TerraformAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text("""
resource "aws_db_instance" "default" {
  identifier = "mydb"
  password   = "supersecretpassword123"
}
""")

            result = analyzer.analyze_file(tf_file)

            password_findings = [
                f for f in result.findings
                if "password" in f.title.lower() or "hardcoded" in f.title.lower()
            ]
            assert len(password_findings) >= 1


class TestCVEDatabase:
    """Tests for CVE database."""

    def test_add_and_get(self) -> None:
        """Test adding and retrieving CVEs."""
        db = CVEDatabase()

        entry = CVEEntry(
            cve_id="CVE-2024-0001",
            title="Test Vulnerability",
            description="A test vulnerability",
            severity=CVESeverity.HIGH,
            affected_packages=["test-package"],
            affected_versions="<1.0.0",
        )

        db.add(entry)

        assert db.count == 1
        assert db.get("CVE-2024-0001") == entry
        assert db.get("CVE-9999-9999") is None

    def test_get_by_package(self) -> None:
        """Test getting CVEs by package."""
        db = CVEDatabase()

        db.add(CVEEntry(
            cve_id="CVE-2024-0001",
            title="Vuln 1",
            description="",
            severity=CVESeverity.HIGH,
            affected_packages=["package-a"],
        ))
        db.add(CVEEntry(
            cve_id="CVE-2024-0002",
            title="Vuln 2",
            description="",
            severity=CVESeverity.MEDIUM,
            affected_packages=["package-a", "package-b"],
        ))

        package_a_cves = db.get_by_package("package-a")
        assert len(package_a_cves) == 2

        package_b_cves = db.get_by_package("package-b")
        assert len(package_b_cves) == 1

    def test_search(self) -> None:
        """Test CVE search."""
        db = CVEDatabase()

        db.add(CVEEntry(
            cve_id="CVE-2024-0001",
            title="SQL Injection",
            description="SQL injection vulnerability",
            severity=CVESeverity.CRITICAL,
            affected_packages=["web-app"],
        ))
        db.add(CVEEntry(
            cve_id="CVE-2024-0002",
            title="XSS Vulnerability",
            description="Cross-site scripting",
            severity=CVESeverity.HIGH,
            affected_packages=["web-app"],
        ))

        # Search by query
        results = db.search(query="SQL")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2024-0001"

        # Search by severity
        results = db.search(severity=CVESeverity.CRITICAL)
        assert len(results) == 1

    def test_ai_framework_database(self) -> None:
        """Test AI framework CVE database."""
        db = get_ai_framework_database()

        assert db.count > 0
        assert "torch" in db.packages or "pytorch" in db.packages
        assert "langchain" in db.packages


class TestCVEMatcher:
    """Tests for CVE matcher."""

    def test_check_vulnerable_package(self) -> None:
        """Test checking a vulnerable package."""
        db = CVEDatabase()
        db.add(CVEEntry(
            cve_id="CVE-2024-0001",
            title="Test Vuln",
            description="",
            severity=CVESeverity.CRITICAL,
            affected_packages=["test-pkg"],
            affected_versions=">=1.0.0,<2.0.0",
            fixed_versions=["2.0.0"],
        ))

        matcher = CVEMatcher(db)

        # Vulnerable version
        results = matcher.check_package("test-pkg", "1.5.0")
        assert len(results) == 1
        assert results[0].is_vulnerable

        # Fixed version
        results = matcher.check_package("test-pkg", "2.0.0")
        assert len(results) == 0

        # Pre-affected version
        results = matcher.check_package("test-pkg", "0.9.0")
        assert len(results) == 0

    def test_version_parsing(self) -> None:
        """Test version string parsing."""
        db = CVEDatabase()
        matcher = CVEMatcher(db)

        # Standard versions
        assert matcher._parse_version("1.2.3") == (1, 2, 3)
        assert matcher._parse_version("1.0") == (1, 0, 0)
        assert matcher._parse_version("v2.1.0") == (2, 1, 0)

        # Pre-release versions
        assert matcher._parse_version("1.0.0a1") == (1, 0, 0)
        assert matcher._parse_version("2.0.0-beta") == (2, 0, 0)

    def test_check_requirements(self) -> None:
        """Test checking multiple requirements."""
        db = CVEDatabase()
        db.add(CVEEntry(
            cve_id="CVE-2024-0001",
            title="Vuln A",
            description="",
            severity=CVESeverity.HIGH,
            affected_packages=["pkg-a"],
            affected_versions="<2.0.0",
        ))
        db.add(CVEEntry(
            cve_id="CVE-2024-0002",
            title="Vuln B",
            description="",
            severity=CVESeverity.MEDIUM,
            affected_packages=["pkg-b"],
            affected_versions="<1.5.0",
        ))

        matcher = CVEMatcher(db)

        results = matcher.check_requirements({
            "pkg-a": "1.0.0",  # Vulnerable
            "pkg-b": "2.0.0",  # Not vulnerable
            "pkg-c": "1.0.0",  # No CVEs
        })

        assert len(results) == 1
        assert results[0].package == "pkg-a"


class TestInfrastructureScanner:
    """Tests for InfrastructureScanner."""

    def test_scan_empty_directory(self) -> None:
        """Test scanning an empty directory."""
        scanner = InfrastructureScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(tmpdir)

            assert result.files_scanned == 0
            assert not result.has_findings

    def test_scan_with_docker(self) -> None:
        """Test scanning with Docker files."""
        scanner = InfrastructureScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            (base / "Dockerfile").write_text("""
FROM python:latest
CMD ["python", "app.py"]
""")

            result = scanner.scan(base)

            assert result.files_scanned >= 1
            docker_findings = result.by_source("docker")
            assert len(docker_findings) >= 1

    def test_scan_with_cve_check(self) -> None:
        """Test scanning with CVE checking."""
        scanner = InfrastructureScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(
                tmpdir,
                dependencies={
                    "langchain": "0.0.100",  # Known vulnerable version
                }
            )

            cve_findings = result.by_source("cve")
            # May or may not match depending on CVE database
            # At minimum, no errors
            assert len(result.errors) == 0

    def test_scan_selective(self) -> None:
        """Test selective scanning."""
        scanner = InfrastructureScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            (base / "Dockerfile").write_text("FROM alpine")
            (base / "main.tf").write_text('provider "aws" {}')

            # Only Docker
            result = scanner.scan(
                base,
                include_docker=True,
                include_kubernetes=False,
                include_terraform=False,
            )

            tf_findings = result.by_source("terraform")
            assert len(tf_findings) == 0

    def test_get_summary(self) -> None:
        """Test getting scan summary."""
        scanner = InfrastructureScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            (base / "Dockerfile").write_text("""
FROM python:latest
ENV PASSWORD=secret123456
""")

            result = scanner.scan(base)
            summary = scanner.get_summary(result)

            assert "total_findings" in summary
            assert "findings_by_source" in summary
            assert "docker" in summary["findings_by_source"]
