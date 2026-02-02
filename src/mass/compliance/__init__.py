"""Compliance assessment module.

Maps security findings to compliance frameworks including
OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, and EU AI Act.
"""

from mass.compliance.assessor import ComplianceAssessor, AssessmentResult
from mass.compliance.mappings import (
    ComplianceMapping,
    FrameworkRequirement,
    get_framework_requirements,
)

__all__ = [
    "ComplianceAssessor",
    "AssessmentResult",
    "ComplianceMapping",
    "FrameworkRequirement",
    "get_framework_requirements",
]
