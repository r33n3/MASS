"""Compliance assessor module.

Assesses security findings against compliance frameworks
and generates compliance reports.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mass.core.findings import Finding
from mass.core.types import FrameworkType, Severity
from mass.compliance.mappings import (
    ComplianceMapping,
    FrameworkRequirement,
    RequirementStatus,
    get_framework_requirements,
    get_mapping_for_category,
    CATEGORY_MAPPINGS,
)


@dataclass
class RequirementAssessment:
    """Assessment result for a single requirement."""

    requirement: FrameworkRequirement
    status: RequirementStatus = RequirementStatus.NOT_ASSESSED
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "requirement_id": self.requirement.id,
            "requirement_name": self.requirement.name,
            "status": self.status.value,
            "findings_count": len(self.findings),
            "finding_ids": [f.id for f in self.findings],
            "risk_score": self.risk_score,
            "notes": self.notes,
        }


@dataclass
class FrameworkAssessment:
    """Assessment result for an entire framework."""

    framework: FrameworkType
    assessed_at: datetime = field(default_factory=datetime.utcnow)

    # Results
    requirements: dict[str, RequirementAssessment] = field(default_factory=dict)

    # Summary
    total_requirements: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    partial_count: int = 0
    not_applicable_count: int = 0
    not_assessed_count: int = 0

    # Scores
    compliance_score: float = 0.0  # 0-100
    risk_score: float = 0.0  # Weighted risk

    def calculate_scores(self) -> None:
        """Calculate compliance and risk scores."""
        self.total_requirements = len(self.requirements)
        self.compliant_count = 0
        self.non_compliant_count = 0
        self.partial_count = 0
        self.not_applicable_count = 0
        self.not_assessed_count = 0

        total_weight = 0.0
        weighted_compliance = 0.0

        for req_id, assessment in self.requirements.items():
            weight = assessment.requirement.severity_weight
            total_weight += weight

            if assessment.status == RequirementStatus.COMPLIANT:
                self.compliant_count += 1
                weighted_compliance += weight
            elif assessment.status == RequirementStatus.NON_COMPLIANT:
                self.non_compliant_count += 1
            elif assessment.status == RequirementStatus.PARTIAL:
                self.partial_count += 1
                weighted_compliance += weight * 0.5
            elif assessment.status == RequirementStatus.NOT_APPLICABLE:
                self.not_applicable_count += 1
                weighted_compliance += weight  # N/A counts as compliant
            else:
                self.not_assessed_count += 1

        # Calculate scores
        if total_weight > 0:
            self.compliance_score = (weighted_compliance / total_weight) * 100
        else:
            self.compliance_score = 100.0

        # Risk score based on non-compliant requirements
        if self.total_requirements > 0:
            self.risk_score = (
                self.non_compliant_count + self.partial_count * 0.5
            ) / self.total_requirements

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework.value,
            "assessed_at": self.assessed_at.isoformat(),
            "compliance_score": round(self.compliance_score, 1),
            "risk_score": round(self.risk_score, 3),
            "summary": {
                "total_requirements": self.total_requirements,
                "compliant": self.compliant_count,
                "non_compliant": self.non_compliant_count,
                "partial": self.partial_count,
                "not_applicable": self.not_applicable_count,
                "not_assessed": self.not_assessed_count,
            },
            "requirements": {
                req_id: assessment.to_dict()
                for req_id, assessment in self.requirements.items()
            },
        }


@dataclass
class AssessmentResult:
    """Complete compliance assessment result."""

    scan_id: str
    assessed_at: datetime = field(default_factory=datetime.utcnow)

    # Framework assessments
    frameworks: dict[FrameworkType, FrameworkAssessment] = field(default_factory=dict)

    # Overall scores
    overall_compliance_score: float = 0.0
    overall_risk_score: float = 0.0

    # Findings summary
    total_findings: int = 0
    mapped_findings: int = 0
    unmapped_findings: int = 0

    def calculate_overall_scores(self) -> None:
        """Calculate overall compliance and risk scores."""
        if not self.frameworks:
            return

        total_score = 0.0
        total_risk = 0.0
        count = len(self.frameworks)

        for framework_assessment in self.frameworks.values():
            framework_assessment.calculate_scores()
            total_score += framework_assessment.compliance_score
            total_risk += framework_assessment.risk_score

        self.overall_compliance_score = total_score / count if count > 0 else 0.0
        self.overall_risk_score = total_risk / count if count > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "assessed_at": self.assessed_at.isoformat(),
            "overall_compliance_score": round(self.overall_compliance_score, 1),
            "overall_risk_score": round(self.overall_risk_score, 3),
            "findings_summary": {
                "total": self.total_findings,
                "mapped": self.mapped_findings,
                "unmapped": self.unmapped_findings,
            },
            "frameworks": {
                fw.value: assessment.to_dict()
                for fw, assessment in self.frameworks.items()
            },
        }


class ComplianceAssessor:
    """Assesses findings against compliance frameworks.

    The assessor maps security findings to compliance requirements
    and calculates compliance scores.
    """

    def __init__(
        self,
        frameworks: list[FrameworkType] | None = None,
    ) -> None:
        """Initialize the assessor.

        Args:
            frameworks: Frameworks to assess against.
                       Defaults to OWASP LLM and MITRE ATLAS.
        """
        self.frameworks = frameworks or [
            FrameworkType.OWASP_LLM,
            FrameworkType.MITRE_ATLAS,
        ]

    def assess(
        self,
        findings: list[Finding],
        scan_id: str = "",
    ) -> AssessmentResult:
        """Assess findings against compliance frameworks.

        Args:
            findings: List of security findings.
            scan_id: Optional scan ID for tracking.

        Returns:
            AssessmentResult with compliance scores.
        """
        result = AssessmentResult(scan_id=scan_id)
        result.total_findings = len(findings)

        # Initialize framework assessments
        for framework in self.frameworks:
            requirements = get_framework_requirements(framework)
            assessment = FrameworkAssessment(framework=framework)

            # Initialize all requirements as compliant (no findings)
            for req_id, req in requirements.items():
                assessment.requirements[req_id] = RequirementAssessment(
                    requirement=req,
                    status=RequirementStatus.COMPLIANT,
                )

            result.frameworks[framework] = assessment

        # Map findings to requirements
        mapped_count = 0
        for finding in findings:
            mapping = get_mapping_for_category(finding.category)
            if not mapping:
                continue

            mapped_count += 1
            self._apply_finding_to_frameworks(finding, mapping, result)

        result.mapped_findings = mapped_count
        result.unmapped_findings = result.total_findings - mapped_count

        # Calculate scores
        result.calculate_overall_scores()

        return result

    def _apply_finding_to_frameworks(
        self,
        finding: Finding,
        mapping: ComplianceMapping,
        result: AssessmentResult,
    ) -> None:
        """Apply a finding to framework requirements."""
        # Apply to OWASP LLM
        if FrameworkType.OWASP_LLM in result.frameworks:
            for req_id in mapping.owasp_llm:
                self._apply_finding_to_requirement(
                    finding,
                    req_id,
                    result.frameworks[FrameworkType.OWASP_LLM],
                )

        # Apply to MITRE ATLAS
        if FrameworkType.MITRE_ATLAS in result.frameworks:
            for req_id in mapping.mitre_atlas:
                self._apply_finding_to_requirement(
                    finding,
                    req_id,
                    result.frameworks[FrameworkType.MITRE_ATLAS],
                )

        # Apply to NIST AI RMF
        if FrameworkType.NIST_AI_RMF in result.frameworks:
            for req_id in mapping.nist_ai_rmf:
                self._apply_finding_to_requirement(
                    finding,
                    req_id,
                    result.frameworks[FrameworkType.NIST_AI_RMF],
                )

        # Apply to EU AI Act
        if FrameworkType.EU_AI_ACT in result.frameworks:
            for req_id in mapping.eu_ai_act:
                self._apply_finding_to_requirement(
                    finding,
                    req_id,
                    result.frameworks[FrameworkType.EU_AI_ACT],
                )

    def _apply_finding_to_requirement(
        self,
        finding: Finding,
        req_id: str,
        framework_assessment: FrameworkAssessment,
    ) -> None:
        """Apply a finding to a specific requirement."""
        if req_id not in framework_assessment.requirements:
            return

        assessment = framework_assessment.requirements[req_id]
        assessment.findings.append(finding)

        # Determine status based on severity
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            assessment.status = RequirementStatus.NON_COMPLIANT
        elif finding.severity == Severity.MEDIUM:
            if assessment.status != RequirementStatus.NON_COMPLIANT:
                assessment.status = RequirementStatus.PARTIAL
        elif assessment.status == RequirementStatus.COMPLIANT:
            # Low/info findings don't change compliant status
            pass

        # Calculate risk score for this requirement
        severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.2,
            Severity.INFO: 0.1,
        }
        assessment.risk_score = max(
            assessment.risk_score,
            severity_weights.get(finding.severity, 0.0),
        )

    def assess_single_framework(
        self,
        findings: list[Finding],
        framework: FrameworkType,
        scan_id: str = "",
    ) -> FrameworkAssessment:
        """Assess findings against a single framework.

        Args:
            findings: List of security findings.
            framework: Framework to assess against.
            scan_id: Optional scan ID.

        Returns:
            FrameworkAssessment for the specified framework.
        """
        # Temporarily set frameworks and assess
        original_frameworks = self.frameworks
        self.frameworks = [framework]

        result = self.assess(findings, scan_id)

        self.frameworks = original_frameworks

        return result.frameworks.get(framework, FrameworkAssessment(framework=framework))

    def get_non_compliant_requirements(
        self,
        result: AssessmentResult,
        framework: FrameworkType | None = None,
    ) -> list[RequirementAssessment]:
        """Get list of non-compliant requirements.

        Args:
            result: Assessment result.
            framework: Optional framework filter.

        Returns:
            List of non-compliant RequirementAssessments.
        """
        non_compliant = []

        frameworks_to_check = (
            [framework] if framework else list(result.frameworks.keys())
        )

        for fw in frameworks_to_check:
            if fw not in result.frameworks:
                continue
            for assessment in result.frameworks[fw].requirements.values():
                if assessment.status in (
                    RequirementStatus.NON_COMPLIANT,
                    RequirementStatus.PARTIAL,
                ):
                    non_compliant.append(assessment)

        return sorted(non_compliant, key=lambda a: -a.risk_score)

    def generate_compliance_summary(
        self,
        result: AssessmentResult,
    ) -> dict[str, Any]:
        """Generate a human-readable compliance summary.

        Args:
            result: Assessment result.

        Returns:
            Dictionary with summary information.
        """
        summary = {
            "overall": {
                "compliance_score": f"{result.overall_compliance_score:.1f}%",
                "risk_level": self._risk_to_level(result.overall_risk_score),
                "total_findings": result.total_findings,
            },
            "frameworks": {},
            "top_issues": [],
        }

        # Framework summaries
        for fw, assessment in result.frameworks.items():
            summary["frameworks"][fw.value] = {
                "compliance_score": f"{assessment.compliance_score:.1f}%",
                "non_compliant_count": assessment.non_compliant_count,
                "partial_count": assessment.partial_count,
            }

        # Top issues
        non_compliant = self.get_non_compliant_requirements(result)
        for req_assessment in non_compliant[:5]:
            summary["top_issues"].append({
                "requirement": req_assessment.requirement.id,
                "name": req_assessment.requirement.name,
                "framework": req_assessment.requirement.framework.value,
                "findings_count": len(req_assessment.findings),
                "status": req_assessment.status.value,
            })

        return summary

    def _risk_to_level(self, risk_score: float) -> str:
        """Convert risk score to human-readable level."""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        elif risk_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
