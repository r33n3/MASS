"""JSON format report generator.

Generates structured JSON reports for API consumption and data exchange.
"""

import json
from datetime import datetime
from typing import Any

from mass.core.findings import Finding, FindingSummary
from mass.compliance.assessor import AssessmentResult
from mass.orchestration.service import ScanResult


class JsonFormatter:
    """Generates JSON format reports."""

    def __init__(
        self,
        include_evidence: bool = True,
        include_remediation: bool = True,
        pretty: bool = True,
    ) -> None:
        """Initialize the JSON formatter.

        Args:
            include_evidence: Whether to include evidence details.
            include_remediation: Whether to include remediation guidance.
            pretty: Whether to pretty-print JSON.
        """
        self.include_evidence = include_evidence
        self.include_remediation = include_remediation
        self.pretty = pretty

    def format(
        self,
        findings: list[Finding],
        scan_id: str = "",
        scan_result: ScanResult | None = None,
        compliance_result: AssessmentResult | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate JSON report from findings.

        Args:
            findings: List of security findings.
            scan_id: Optional scan ID.
            scan_result: Optional scan result.
            compliance_result: Optional compliance assessment.
            metadata: Optional additional metadata.

        Returns:
            Report as dictionary.
        """
        summary = FindingSummary.from_findings(findings)

        report: dict[str, Any] = {
            "version": "1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "scan_id": scan_id,
            "summary": {
                "total_findings": summary.total,
                "by_severity": {
                    "critical": summary.critical_count,
                    "high": summary.high_count,
                    "medium": summary.medium_count,
                    "low": summary.low_count,
                    "info": summary.info_count,
                },
                "by_category": summary.by_category,
                "by_component": summary.by_component,
            },
            "findings": [self._format_finding(f) for f in findings],
        }

        # Add scan result if provided
        if scan_result:
            report["scan"] = {
                "deployment_id": scan_result.deployment_id,
                "profile": scan_result.profile_name,
                "status": scan_result.status.value,
                "started_at": scan_result.started_at.isoformat() if scan_result.started_at else None,
                "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                "duration_seconds": scan_result.duration_seconds,
                "jobs_completed": scan_result.jobs_completed,
                "jobs_failed": scan_result.jobs_failed,
            }

        # Add compliance result if provided
        if compliance_result:
            report["compliance"] = compliance_result.to_dict()

        # Add metadata if provided
        if metadata:
            report["metadata"] = metadata

        return report

    def _format_finding(self, finding: Finding) -> dict[str, Any]:
        """Format a single finding."""
        result: dict[str, Any] = {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "category": finding.category.value,
            "component_type": finding.component_type.value,
            "component_name": finding.component_name,
            "confidence": finding.confidence,
            "detected_at": finding.detected_at.isoformat(),
        }

        # Add location if available
        if finding.file_path:
            result["location"] = {
                "file": finding.file_path,
                "line": finding.line_number,
            }

        # Add compliance mappings
        if finding.cwe_ids or finding.owasp_ids or finding.mitre_ids:
            result["compliance"] = {
                "cwe": finding.cwe_ids,
                "owasp": finding.owasp_ids,
                "mitre": finding.mitre_ids,
            }

        # Add evidence if enabled
        if self.include_evidence and finding.evidence:
            result["evidence"] = [
                {
                    "type": ev.type,
                    "content": ev.content,
                    "source_file": ev.source_file,
                    "source_line": ev.source_line,
                }
                for ev in finding.evidence
            ]

        # Add remediation if enabled
        if self.include_remediation and finding.remediation:
            result["remediation"] = {
                "summary": finding.remediation.summary,
                "steps": finding.remediation.steps,
                "references": finding.remediation.references,
                "estimated_effort": finding.remediation.estimated_effort,
            }

        # Add tags
        if finding.tags:
            result["tags"] = finding.tags

        return result

    def format_to_string(
        self,
        findings: list[Finding],
        scan_id: str = "",
        scan_result: ScanResult | None = None,
        compliance_result: AssessmentResult | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Generate JSON report as string.

        Args:
            findings: List of security findings.
            scan_id: Optional scan ID.
            scan_result: Optional scan result.
            compliance_result: Optional compliance assessment.
            metadata: Optional additional metadata.

        Returns:
            JSON string.
        """
        report = self.format(
            findings, scan_id, scan_result, compliance_result, metadata
        )
        if self.pretty:
            return json.dumps(report, indent=2, default=str)
        return json.dumps(report, default=str)

    def format_findings_only(self, findings: list[Finding]) -> str:
        """Generate minimal JSON with just findings.

        Args:
            findings: List of security findings.

        Returns:
            JSON string with findings array.
        """
        formatted = [self._format_finding(f) for f in findings]
        if self.pretty:
            return json.dumps(formatted, indent=2, default=str)
        return json.dumps(formatted, default=str)
