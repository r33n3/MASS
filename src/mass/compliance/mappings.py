"""Compliance framework mappings.

Maps attack categories to specific framework requirements
for OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, EU AI Act, and more.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mass.core.types import AttackCategory, FrameworkType


class RequirementStatus(str, Enum):
    """Status of a compliance requirement."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


@dataclass
class FrameworkRequirement:
    """A single requirement from a compliance framework."""

    id: str
    name: str
    description: str
    framework: FrameworkType
    category: str = ""
    severity_weight: float = 1.0
    references: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)

    # Assessment results
    status: RequirementStatus = RequirementStatus.NOT_ASSESSED
    finding_count: int = 0
    finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "framework": self.framework.value,
            "category": self.category,
            "status": self.status.value,
            "finding_count": self.finding_count,
            "finding_ids": self.finding_ids,
            "references": self.references,
        }


@dataclass
class ComplianceMapping:
    """Mapping between attack categories and framework requirements."""

    category: AttackCategory
    owasp_llm: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)
    nist_ai_rmf: list[str] = field(default_factory=list)
    eu_ai_act: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)


# OWASP LLM Top 10 2025 Requirements
OWASP_LLM_REQUIREMENTS: dict[str, FrameworkRequirement] = {
    "LLM01": FrameworkRequirement(
        id="LLM01",
        name="Prompt Injection",
        description="Manipulating LLMs via crafted inputs to exfiltrate data, run unauthorized actions, or manipulate outputs.",
        framework=FrameworkType.OWASP_LLM,
        category="Input Validation",
        severity_weight=1.0,
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "LLM02": FrameworkRequirement(
        id="LLM02",
        name="Sensitive Information Disclosure",
        description="Unintended revelation of sensitive information through LLM responses.",
        framework=FrameworkType.OWASP_LLM,
        category="Data Protection",
        severity_weight=0.9,
    ),
    "LLM03": FrameworkRequirement(
        id="LLM03",
        name="Supply Chain Vulnerabilities",
        description="Risks from third-party components, training data, or pre-trained models.",
        framework=FrameworkType.OWASP_LLM,
        category="Supply Chain",
        severity_weight=0.85,
    ),
    "LLM04": FrameworkRequirement(
        id="LLM04",
        name="Data and Model Poisoning",
        description="Manipulation of training or fine-tuning data to introduce vulnerabilities.",
        framework=FrameworkType.OWASP_LLM,
        category="Data Integrity",
        severity_weight=0.9,
    ),
    "LLM05": FrameworkRequirement(
        id="LLM05",
        name="Improper Output Handling",
        description="Inadequate validation of LLM outputs before downstream use.",
        framework=FrameworkType.OWASP_LLM,
        category="Output Validation",
        severity_weight=0.8,
    ),
    "LLM06": FrameworkRequirement(
        id="LLM06",
        name="Excessive Agency",
        description="LLM systems with too much autonomy or capability.",
        framework=FrameworkType.OWASP_LLM,
        category="Access Control",
        severity_weight=0.95,
    ),
    "LLM07": FrameworkRequirement(
        id="LLM07",
        name="System Prompt Leakage",
        description="Exposure of system prompts that could reveal sensitive instructions.",
        framework=FrameworkType.OWASP_LLM,
        category="Configuration Security",
        severity_weight=0.75,
    ),
    "LLM08": FrameworkRequirement(
        id="LLM08",
        name="Vector and Embedding Weaknesses",
        description="Vulnerabilities in RAG systems and vector databases.",
        framework=FrameworkType.OWASP_LLM,
        category="Data Security",
        severity_weight=0.7,
    ),
    "LLM09": FrameworkRequirement(
        id="LLM09",
        name="Misinformation",
        description="Generation of false or misleading information.",
        framework=FrameworkType.OWASP_LLM,
        category="Output Quality",
        severity_weight=0.6,
    ),
    "LLM10": FrameworkRequirement(
        id="LLM10",
        name="Unbounded Consumption",
        description="Resource exhaustion through excessive queries or processing.",
        framework=FrameworkType.OWASP_LLM,
        category="Availability",
        severity_weight=0.65,
    ),
}

# MITRE ATLAS Techniques (subset)
MITRE_ATLAS_REQUIREMENTS: dict[str, FrameworkRequirement] = {
    "AML.T0000": FrameworkRequirement(
        id="AML.T0000",
        name="Data Poisoning",
        description="Adversary manipulates training data to introduce backdoors.",
        framework=FrameworkType.MITRE_ATLAS,
        category="ML Attack Lifecycle",
        severity_weight=0.9,
    ),
    "AML.T0015": FrameworkRequirement(
        id="AML.T0015",
        name="Prompt Injection",
        description="Adversary crafts inputs to manipulate model behavior.",
        framework=FrameworkType.MITRE_ATLAS,
        category="ML Attack Lifecycle",
        severity_weight=1.0,
    ),
    "AML.T0024": FrameworkRequirement(
        id="AML.T0024",
        name="Exfiltration via ML Inference API",
        description="Using inference APIs to extract sensitive data.",
        framework=FrameworkType.MITRE_ATLAS,
        category="Exfiltration",
        severity_weight=0.85,
    ),
    "AML.T0025": FrameworkRequirement(
        id="AML.T0025",
        name="Model Evasion",
        description="Crafting inputs to evade model detection.",
        framework=FrameworkType.MITRE_ATLAS,
        category="Evasion",
        severity_weight=0.75,
    ),
    "AML.T0035": FrameworkRequirement(
        id="AML.T0035",
        name="ML Supply Chain Compromise",
        description="Compromise of ML supply chain components.",
        framework=FrameworkType.MITRE_ATLAS,
        category="Supply Chain",
        severity_weight=0.9,
    ),
    "AML.T0040": FrameworkRequirement(
        id="AML.T0040",
        name="Model Extraction",
        description="Extracting model architecture or weights.",
        framework=FrameworkType.MITRE_ATLAS,
        category="Collection",
        severity_weight=0.8,
    ),
    "AML.T0043": FrameworkRequirement(
        id="AML.T0043",
        name="Craft Adversarial Data",
        description="Creating adversarial examples to fool models.",
        framework=FrameworkType.MITRE_ATLAS,
        category="Resource Development",
        severity_weight=0.7,
    ),
}

# NIST AI RMF Categories
NIST_AI_RMF_REQUIREMENTS: dict[str, FrameworkRequirement] = {
    "GOVERN-1": FrameworkRequirement(
        id="GOVERN-1",
        name="Governance Policies",
        description="Policies for AI system governance are established.",
        framework=FrameworkType.NIST_AI_RMF,
        category="Govern",
        severity_weight=0.5,
    ),
    "MAP-1": FrameworkRequirement(
        id="MAP-1",
        name="Risk Identification",
        description="AI system risks are identified and documented.",
        framework=FrameworkType.NIST_AI_RMF,
        category="Map",
        severity_weight=0.6,
    ),
    "MEASURE-1": FrameworkRequirement(
        id="MEASURE-1",
        name="Risk Assessment",
        description="AI system risks are measured and monitored.",
        framework=FrameworkType.NIST_AI_RMF,
        category="Measure",
        severity_weight=0.7,
    ),
    "MANAGE-1": FrameworkRequirement(
        id="MANAGE-1",
        name="Risk Mitigation",
        description="AI system risks are mitigated or managed.",
        framework=FrameworkType.NIST_AI_RMF,
        category="Manage",
        severity_weight=0.8,
    ),
    "MANAGE-2": FrameworkRequirement(
        id="MANAGE-2",
        name="Incident Response",
        description="Processes exist for AI incident response.",
        framework=FrameworkType.NIST_AI_RMF,
        category="Manage",
        severity_weight=0.75,
    ),
}

# EU AI Act Requirements
EU_AI_ACT_REQUIREMENTS: dict[str, FrameworkRequirement] = {
    "AIA-9": FrameworkRequirement(
        id="AIA-9",
        name="Risk Management System",
        description="High-risk AI systems require risk management.",
        framework=FrameworkType.EU_AI_ACT,
        category="Risk Management",
        severity_weight=0.8,
    ),
    "AIA-10": FrameworkRequirement(
        id="AIA-10",
        name="Data Governance",
        description="Training, validation, and test datasets must be relevant and representative.",
        framework=FrameworkType.EU_AI_ACT,
        category="Data Governance",
        severity_weight=0.75,
    ),
    "AIA-13": FrameworkRequirement(
        id="AIA-13",
        name="Transparency",
        description="AI systems must be transparent to users.",
        framework=FrameworkType.EU_AI_ACT,
        category="Transparency",
        severity_weight=0.6,
    ),
    "AIA-14": FrameworkRequirement(
        id="AIA-14",
        name="Human Oversight",
        description="AI systems must allow for human oversight.",
        framework=FrameworkType.EU_AI_ACT,
        category="Human Oversight",
        severity_weight=0.85,
    ),
    "AIA-15": FrameworkRequirement(
        id="AIA-15",
        name="Accuracy & Robustness",
        description="AI systems must be accurate, robust, and cybersecure.",
        framework=FrameworkType.EU_AI_ACT,
        category="Technical Requirements",
        severity_weight=0.9,
    ),
}

# Attack category to compliance mapping
CATEGORY_MAPPINGS: dict[AttackCategory, ComplianceMapping] = {
    AttackCategory.PROMPT_INJECTION: ComplianceMapping(
        category=AttackCategory.PROMPT_INJECTION,
        owasp_llm=["LLM01"],
        mitre_atlas=["AML.T0015"],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-15"],
        cwe=["CWE-74", "CWE-77"],
    ),
    AttackCategory.SENSITIVE_INFO: ComplianceMapping(
        category=AttackCategory.SENSITIVE_INFO,
        owasp_llm=["LLM02"],
        mitre_atlas=["AML.T0024"],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-10"],
        cwe=["CWE-200", "CWE-359"],
    ),
    AttackCategory.SUPPLY_CHAIN: ComplianceMapping(
        category=AttackCategory.SUPPLY_CHAIN,
        owasp_llm=["LLM03"],
        mitre_atlas=["AML.T0035"],
        nist_ai_rmf=["MAP-1", "MANAGE-1"],
        eu_ai_act=["AIA-9"],
        cwe=["CWE-1357"],
    ),
    AttackCategory.DATA_MODEL_POISONING: ComplianceMapping(
        category=AttackCategory.DATA_MODEL_POISONING,
        owasp_llm=["LLM04"],
        mitre_atlas=["AML.T0000"],
        nist_ai_rmf=["MEASURE-1"],
        eu_ai_act=["AIA-10"],
        cwe=["CWE-1395"],
    ),
    AttackCategory.IMPROPER_OUTPUT: ComplianceMapping(
        category=AttackCategory.IMPROPER_OUTPUT,
        owasp_llm=["LLM05"],
        mitre_atlas=["AML.T0025"],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-15"],
        cwe=["CWE-116", "CWE-79"],
    ),
    AttackCategory.EXCESSIVE_AGENCY: ComplianceMapping(
        category=AttackCategory.EXCESSIVE_AGENCY,
        owasp_llm=["LLM06"],
        mitre_atlas=[],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-14"],
        cwe=["CWE-269", "CWE-250"],
    ),
    AttackCategory.SYSTEM_PROMPT_LEAKAGE: ComplianceMapping(
        category=AttackCategory.SYSTEM_PROMPT_LEAKAGE,
        owasp_llm=["LLM07"],
        mitre_atlas=["AML.T0024"],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-13"],
        cwe=["CWE-200", "CWE-215"],
    ),
    AttackCategory.VECTOR_EMBEDDING: ComplianceMapping(
        category=AttackCategory.VECTOR_EMBEDDING,
        owasp_llm=["LLM08"],
        mitre_atlas=["AML.T0043"],
        nist_ai_rmf=["MEASURE-1"],
        eu_ai_act=["AIA-10"],
        cwe=["CWE-1395"],
    ),
    AttackCategory.MISINFORMATION: ComplianceMapping(
        category=AttackCategory.MISINFORMATION,
        owasp_llm=["LLM09"],
        mitre_atlas=[],
        nist_ai_rmf=["MEASURE-1"],
        eu_ai_act=["AIA-13"],
        cwe=[],
    ),
    AttackCategory.UNBOUNDED_CONSUMPTION: ComplianceMapping(
        category=AttackCategory.UNBOUNDED_CONSUMPTION,
        owasp_llm=["LLM10"],
        mitre_atlas=[],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-15"],
        cwe=["CWE-400", "CWE-770"],
    ),
    AttackCategory.JAILBREAK: ComplianceMapping(
        category=AttackCategory.JAILBREAK,
        owasp_llm=["LLM01"],
        mitre_atlas=["AML.T0015", "AML.T0025"],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-15"],
        cwe=["CWE-74"],
    ),
    AttackCategory.SECRETS_EXPOSURE: ComplianceMapping(
        category=AttackCategory.SECRETS_EXPOSURE,
        owasp_llm=["LLM02", "LLM07"],
        mitre_atlas=["AML.T0024"],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-15"],
        cwe=["CWE-798", "CWE-312"],
    ),
    AttackCategory.INSECURE_PLUGIN: ComplianceMapping(
        category=AttackCategory.INSECURE_PLUGIN,
        owasp_llm=["LLM06"],
        mitre_atlas=["AML.T0035"],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-15"],
        cwe=["CWE-284", "CWE-269"],
    ),
    AttackCategory.MODEL_THEFT: ComplianceMapping(
        category=AttackCategory.MODEL_THEFT,
        owasp_llm=["LLM03"],
        mitre_atlas=["AML.T0040"],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-15"],
        cwe=["CWE-200"],
    ),
    AttackCategory.PRIVILEGE_ESCALATION: ComplianceMapping(
        category=AttackCategory.PRIVILEGE_ESCALATION,
        owasp_llm=["LLM06"],
        mitre_atlas=[],
        nist_ai_rmf=["MANAGE-1"],
        eu_ai_act=["AIA-14"],
        cwe=["CWE-269", "CWE-250"],
    ),
}


def get_framework_requirements(
    framework: FrameworkType,
) -> dict[str, FrameworkRequirement]:
    """Get all requirements for a framework.

    Args:
        framework: The compliance framework.

    Returns:
        Dictionary of requirement ID to FrameworkRequirement.
    """
    if framework == FrameworkType.OWASP_LLM:
        return OWASP_LLM_REQUIREMENTS.copy()
    elif framework == FrameworkType.MITRE_ATLAS:
        return MITRE_ATLAS_REQUIREMENTS.copy()
    elif framework == FrameworkType.NIST_AI_RMF:
        return NIST_AI_RMF_REQUIREMENTS.copy()
    elif framework == FrameworkType.EU_AI_ACT:
        return EU_AI_ACT_REQUIREMENTS.copy()
    else:
        return {}


def get_mapping_for_category(category: AttackCategory) -> ComplianceMapping | None:
    """Get compliance mapping for an attack category.

    Args:
        category: The attack category.

    Returns:
        ComplianceMapping if found.
    """
    return CATEGORY_MAPPINGS.get(category)
