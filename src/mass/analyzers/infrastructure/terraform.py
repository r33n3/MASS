"""Terraform configuration analyzer.

Analyzes Terraform files for security issues and misconfigurations.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from mass.core.types import Severity


@dataclass
class TerraformFinding:
    """A security finding from Terraform analysis."""
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: Path
    resource_type: str
    resource_name: str
    line_number: int | None = None
    line_content: str = ""
    remediation: str = ""
    cwe_id: str | None = None


@dataclass
class TerraformAnalysisResult:
    """Result of Terraform configuration analysis."""
    findings: list[TerraformFinding] = field(default_factory=list)
    files_analyzed: int = 0
    resources_analyzed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def by_severity(self, severity: Severity) -> list[TerraformFinding]:
        return [f for f in self.findings if f.severity == severity]


@dataclass
class TerraformRule:
    """A security rule for Terraform analysis."""
    id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    resource_types: list[str]
    pattern: str
    pattern_type: str = "present"  # present, absent
    cwe_id: str | None = None


# Terraform Security Rules
TERRAFORM_RULES = [
    # AWS S3 Rules
    TerraformRule(
        id="TF001",
        severity=Severity.HIGH,
        title="S3 bucket without encryption",
        description="S3 bucket does not have server-side encryption enabled.",
        remediation="Add server_side_encryption_configuration block with AES256 or aws:kms.",
        resource_types=["aws_s3_bucket"],
        pattern=r"server_side_encryption_configuration",
        pattern_type="absent",
        cwe_id="CWE-311",
    ),
    TerraformRule(
        id="TF002",
        severity=Severity.HIGH,
        title="S3 bucket with public access",
        description="S3 bucket allows public access.",
        remediation="Set block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets to true.",
        resource_types=["aws_s3_bucket_public_access_block"],
        pattern=r"(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false",
        pattern_type="present",
        cwe_id="CWE-284",
    ),
    TerraformRule(
        id="TF003",
        severity=Severity.MEDIUM,
        title="S3 bucket without versioning",
        description="S3 bucket does not have versioning enabled.",
        remediation="Enable versioning with versioning { enabled = true }.",
        resource_types=["aws_s3_bucket"],
        pattern=r"versioning\s*\{[^}]*enabled\s*=\s*true",
        pattern_type="absent",
        cwe_id="CWE-693",
    ),

    # AWS Security Group Rules
    TerraformRule(
        id="TF004",
        severity=Severity.CRITICAL,
        title="Security group allows all inbound traffic",
        description="Security group ingress allows traffic from 0.0.0.0/0.",
        remediation="Restrict CIDR blocks to specific IP ranges.",
        resource_types=["aws_security_group", "aws_security_group_rule"],
        pattern=r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        pattern_type="present",
        cwe_id="CWE-284",
    ),
    TerraformRule(
        id="TF005",
        severity=Severity.CRITICAL,
        title="Security group allows SSH from anywhere",
        description="Security group allows SSH (port 22) from 0.0.0.0/0.",
        remediation="Restrict SSH access to specific IP ranges.",
        resource_types=["aws_security_group", "aws_security_group_rule"],
        pattern=r'(?:from_port|to_port)\s*=\s*22.*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
        pattern_type="present",
        cwe_id="CWE-284",
    ),
    TerraformRule(
        id="TF006",
        severity=Severity.CRITICAL,
        title="Security group allows RDP from anywhere",
        description="Security group allows RDP (port 3389) from 0.0.0.0/0.",
        remediation="Restrict RDP access to specific IP ranges.",
        resource_types=["aws_security_group", "aws_security_group_rule"],
        pattern=r'(?:from_port|to_port)\s*=\s*3389.*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
        pattern_type="present",
        cwe_id="CWE-284",
    ),

    # AWS RDS Rules
    TerraformRule(
        id="TF007",
        severity=Severity.HIGH,
        title="RDS instance publicly accessible",
        description="RDS instance is publicly accessible.",
        remediation="Set publicly_accessible = false.",
        resource_types=["aws_db_instance"],
        pattern=r"publicly_accessible\s*=\s*true",
        pattern_type="present",
        cwe_id="CWE-284",
    ),
    TerraformRule(
        id="TF008",
        severity=Severity.HIGH,
        title="RDS instance without encryption",
        description="RDS instance does not have storage encryption enabled.",
        remediation="Set storage_encrypted = true.",
        resource_types=["aws_db_instance"],
        pattern=r"storage_encrypted\s*=\s*true",
        pattern_type="absent",
        cwe_id="CWE-311",
    ),

    # AWS IAM Rules
    TerraformRule(
        id="TF009",
        severity=Severity.CRITICAL,
        title="IAM policy with * actions",
        description="IAM policy allows all actions (*).",
        remediation="Follow least privilege principle; specify only required actions.",
        resource_types=["aws_iam_policy", "aws_iam_policy_document"],
        pattern=r'"Action"\s*:\s*"\*"',
        pattern_type="present",
        cwe_id="CWE-269",
    ),
    TerraformRule(
        id="TF010",
        severity=Severity.CRITICAL,
        title="IAM policy with * resources",
        description="IAM policy applies to all resources (*).",
        remediation="Follow least privilege principle; specify specific resources.",
        resource_types=["aws_iam_policy", "aws_iam_policy_document"],
        pattern=r'"Resource"\s*:\s*"\*"',
        pattern_type="present",
        cwe_id="CWE-269",
    ),

    # AWS EC2 Rules
    TerraformRule(
        id="TF011",
        severity=Severity.MEDIUM,
        title="EC2 instance without IMDSv2",
        description="EC2 instance does not require IMDSv2.",
        remediation="Set metadata_options { http_tokens = \"required\" }.",
        resource_types=["aws_instance", "aws_launch_template"],
        pattern=r'http_tokens\s*=\s*"required"',
        pattern_type="absent",
        cwe_id="CWE-522",
    ),

    # AWS EBS Rules
    TerraformRule(
        id="TF012",
        severity=Severity.HIGH,
        title="EBS volume without encryption",
        description="EBS volume is not encrypted.",
        remediation="Set encrypted = true.",
        resource_types=["aws_ebs_volume"],
        pattern=r"encrypted\s*=\s*true",
        pattern_type="absent",
        cwe_id="CWE-311",
    ),

    # Azure Rules
    TerraformRule(
        id="TF013",
        severity=Severity.HIGH,
        title="Azure storage without HTTPS",
        description="Azure storage account does not require HTTPS.",
        remediation="Set enable_https_traffic_only = true.",
        resource_types=["azurerm_storage_account"],
        pattern=r"enable_https_traffic_only\s*=\s*false",
        pattern_type="present",
        cwe_id="CWE-319",
    ),
    TerraformRule(
        id="TF014",
        severity=Severity.HIGH,
        title="Azure storage public access",
        description="Azure storage account allows public blob access.",
        remediation="Set allow_blob_public_access = false.",
        resource_types=["azurerm_storage_account"],
        pattern=r"allow_blob_public_access\s*=\s*true",
        pattern_type="present",
        cwe_id="CWE-284",
    ),

    # GCP Rules
    TerraformRule(
        id="TF015",
        severity=Severity.HIGH,
        title="GCS bucket with public access",
        description="GCS bucket allows public access.",
        remediation="Remove allUsers or allAuthenticatedUsers bindings.",
        resource_types=["google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"],
        pattern=r'member\s*=\s*"(?:allUsers|allAuthenticatedUsers)"',
        pattern_type="present",
        cwe_id="CWE-284",
    ),
    TerraformRule(
        id="TF016",
        severity=Severity.CRITICAL,
        title="GCP compute firewall allows all traffic",
        description="GCP firewall rule allows traffic from 0.0.0.0/0.",
        remediation="Restrict source_ranges to specific IP ranges.",
        resource_types=["google_compute_firewall"],
        pattern=r'source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        pattern_type="present",
        cwe_id="CWE-284",
    ),

    # Generic Security Rules
    TerraformRule(
        id="TF017",
        severity=Severity.CRITICAL,
        title="Hardcoded password",
        description="Password appears to be hardcoded in Terraform configuration.",
        remediation="Use variables with sensitive = true or secrets manager.",
        resource_types=["*"],
        pattern=r'(?:password|passwd|secret)\s*=\s*"[^"$]{8,}"',
        pattern_type="present",
        cwe_id="CWE-798",
    ),
    TerraformRule(
        id="TF018",
        severity=Severity.CRITICAL,
        title="Hardcoded API key",
        description="API key appears to be hardcoded in Terraform configuration.",
        remediation="Use variables with sensitive = true or secrets manager.",
        resource_types=["*"],
        pattern=r'(?:api_key|apikey|access_key)\s*=\s*"[A-Za-z0-9+/=]{16,}"',
        pattern_type="present",
        cwe_id="CWE-798",
    ),
    TerraformRule(
        id="TF019",
        severity=Severity.MEDIUM,
        title="Variable without sensitive flag",
        description="Variable containing sensitive data is not marked sensitive.",
        remediation="Add sensitive = true to the variable definition.",
        resource_types=["variable"],
        pattern=r'variable\s+"[^"]*(?:password|secret|token|key)[^"]*"\s*\{(?:(?!sensitive\s*=\s*true)[^}])*\}',
        pattern_type="present",
        cwe_id="CWE-532",
    ),
]


class TerraformAnalyzer:
    """Analyzes Terraform configuration files for security issues."""

    FILE_PATTERNS = ["*.tf", "*.tf.json"]

    def __init__(self, rules: list[TerraformRule] | None = None):
        """Initialize Terraform analyzer.

        Args:
            rules: Custom rules. Uses defaults if None.
        """
        self.rules = rules or TERRAFORM_RULES

    def analyze_file(self, file_path: Path) -> TerraformAnalysisResult:
        """Analyze a Terraform file.

        Args:
            file_path: Path to the Terraform file.

        Returns:
            Analysis result with findings.
        """
        result = TerraformAnalysisResult(files_analyzed=1)

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            result.errors.append(f"Could not read {file_path}: {e}")
            return result

        # Extract resources from file
        resources = self._extract_resources(content)
        result.resources_analyzed = len(resources)

        for finding in self._check_content(content, resources, file_path):
            result.findings.append(finding)

        return result

    def analyze_directory(self, directory: Path) -> TerraformAnalysisResult:
        """Analyze all Terraform files in a directory.

        Args:
            directory: Directory to scan.

        Returns:
            Combined analysis result.
        """
        result = TerraformAnalysisResult()

        for tf_file in self._find_terraform_files(directory):
            file_result = self.analyze_file(tf_file)
            result.findings.extend(file_result.findings)
            result.files_analyzed += file_result.files_analyzed
            result.resources_analyzed += file_result.resources_analyzed
            result.errors.extend(file_result.errors)

        return result

    def _extract_resources(self, content: str) -> list[tuple[str, str, int, str]]:
        """Extract resource definitions from Terraform content.

        Returns:
            List of (resource_type, resource_name, line_number, block_content).
        """
        resources = []

        # Pattern to match resource blocks
        resource_pattern = re.compile(
            r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
            re.MULTILINE
        )

        for match in resource_pattern.finditer(content):
            resource_type = match.group(1)
            resource_name = match.group(2)
            line_num = content[:match.start()].count("\n") + 1

            # Extract the block content (simplified - doesn't handle nested braces perfectly)
            start = match.end()
            brace_count = 1
            end = start

            while end < len(content) and brace_count > 0:
                if content[end] == "{":
                    brace_count += 1
                elif content[end] == "}":
                    brace_count -= 1
                end += 1

            block_content = content[match.start():end]
            resources.append((resource_type, resource_name, line_num, block_content))

        return resources

    def _check_content(
        self,
        content: str,
        resources: list[tuple[str, str, int, str]],
        file_path: Path,
    ) -> Iterator[TerraformFinding]:
        """Check content against all rules.

        Args:
            content: Full file content.
            resources: Extracted resources.
            file_path: Source file path.

        Yields:
            TerraformFinding for each rule violation.
        """
        lines = content.splitlines()

        for rule in self.rules:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)

            # Check if rule applies to all resources (*) or specific types
            if "*" in rule.resource_types:
                # Check entire file content
                if rule.pattern_type == "present":
                    for match in pattern.finditer(content):
                        line_num = content[:match.start()].count("\n") + 1
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                        yield TerraformFinding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            file_path=file_path,
                            resource_type="*",
                            resource_name="*",
                            line_number=line_num,
                            line_content=line_content.strip(),
                            remediation=rule.remediation,
                            cwe_id=rule.cwe_id,
                        )
            else:
                # Check specific resource types
                for resource_type, resource_name, line_num, block_content in resources:
                    if resource_type not in rule.resource_types:
                        continue

                    matches_pattern = bool(pattern.search(block_content))

                    if rule.pattern_type == "present" and matches_pattern:
                        # Find the specific line within the block
                        for match in pattern.finditer(block_content):
                            relative_line = block_content[:match.start()].count("\n")
                            actual_line = line_num + relative_line
                            line_content = lines[actual_line - 1] if actual_line <= len(lines) else ""

                            yield TerraformFinding(
                                rule_id=rule.id,
                                severity=rule.severity,
                                title=rule.title,
                                description=rule.description,
                                file_path=file_path,
                                resource_type=resource_type,
                                resource_name=resource_name,
                                line_number=actual_line,
                                line_content=line_content.strip(),
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                            )

                    elif rule.pattern_type == "absent" and not matches_pattern:
                        yield TerraformFinding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            file_path=file_path,
                            resource_type=resource_type,
                            resource_name=resource_name,
                            line_number=line_num,
                            remediation=rule.remediation,
                            cwe_id=rule.cwe_id,
                        )

    def _find_terraform_files(self, directory: Path) -> Iterator[Path]:
        """Find Terraform files in directory."""
        for pattern in self.FILE_PATTERNS:
            yield from directory.rglob(pattern)
