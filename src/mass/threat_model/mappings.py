"""STRIDE-AI mapping tables.

Maps MASS attack categories and attack vector types to the STRIDE-AI
taxonomy, and cross-references each STRIDE-AI category to compliance
frameworks (OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, CWE).
"""

from mass.threat_model.types import StrideAICategory


# ============================================================
# AttackCategory → STRIDE-AI
# ============================================================

ATTACK_CATEGORY_TO_STRIDE: dict[str, StrideAICategory] = {
    # OWASP LLM Top 10
    "prompt_injection": StrideAICategory.PROMPT_INJECTION,
    "sensitive_info": StrideAICategory.DATA_EXFILTRATION,
    "supply_chain": StrideAICategory.MODEL_MANIPULATION,
    "data_model_poisoning": StrideAICategory.DATA_POISONING,
    "improper_output": StrideAICategory.CONTEXT_MANIPULATION,
    "excessive_agency": StrideAICategory.EXCESSIVE_AGENCY,
    "system_prompt_leakage": StrideAICategory.SYSTEM_PROMPT_LEAKAGE,
    "vector_embedding": StrideAICategory.DATA_POISONING,
    "misinformation": StrideAICategory.CONTEXT_MANIPULATION,
    "unbounded_consumption": StrideAICategory.UNBOUNDED_CONSUMPTION,
    # Extended categories
    "jailbreak": StrideAICategory.JAILBREAK,
    "data_leakage": StrideAICategory.DATA_EXFILTRATION,
    "hallucination": StrideAICategory.ATTRIBUTION_FAILURES,
    "bias": StrideAICategory.CONTEXT_MANIPULATION,
    "toxicity": StrideAICategory.CONTEXT_MANIPULATION,
    "secrets_exposure": StrideAICategory.DATA_EXFILTRATION,
    "insecure_plugin": StrideAICategory.TOOL_ABUSE,
    "model_theft": StrideAICategory.MODEL_EXTRACTION,
    "privilege_escalation": StrideAICategory.JAILBREAK,
    "denial_of_service": StrideAICategory.RESOURCE_EXHAUSTION,
}


# ============================================================
# AttackVectorType → STRIDE-AI
# ============================================================

ATTACK_VECTOR_TO_STRIDE: dict[str, StrideAICategory] = {
    "user_input": StrideAICategory.PROMPT_INJECTION,
    "file_upload": StrideAICategory.DATA_POISONING,
    "api_endpoint": StrideAICategory.IDENTITY_SPOOFING,
    "database_query": StrideAICategory.DATA_EXFILTRATION,
    "external_service": StrideAICategory.MODEL_IMPERSONATION,
    "rag_retrieval": StrideAICategory.DATA_POISONING,
    "tool_invocation": StrideAICategory.TOOL_ABUSE,
    "agent_communication": StrideAICategory.CONTEXT_MANIPULATION,
    "context_injection": StrideAICategory.PROMPT_INJECTION,
    "model_inference": StrideAICategory.MODEL_EXTRACTION,
    "memory_access": StrideAICategory.CONTEXT_MANIPULATION,
    "webhook": StrideAICategory.IDENTITY_SPOOFING,
}


# ============================================================
# Topology edge type → applicable STRIDE-AI threats
# ============================================================

EDGE_TYPE_THREATS: dict[str, list[StrideAICategory]] = {
    "data_flow": [
        StrideAICategory.DATA_EXFILTRATION,
        StrideAICategory.DATA_POISONING,
    ],
    "auth": [
        StrideAICategory.IDENTITY_SPOOFING,
        StrideAICategory.MODEL_IMPERSONATION,
    ],
    "tool_call": [
        StrideAICategory.TOOL_ABUSE,
        StrideAICategory.EXCESSIVE_AGENCY,
    ],
    "api_call": [
        StrideAICategory.IDENTITY_SPOOFING,
        StrideAICategory.DATA_EXFILTRATION,
    ],
    "model_query": [
        StrideAICategory.PROMPT_INJECTION,
        StrideAICategory.MODEL_EXTRACTION,
        StrideAICategory.SYSTEM_PROMPT_LEAKAGE,
    ],
}


# ============================================================
# Node type → inherent STRIDE-AI threats
# ============================================================

NODE_TYPE_THREATS: dict[str, list[StrideAICategory]] = {
    "ai_agent": [
        StrideAICategory.JAILBREAK,
        StrideAICategory.EXCESSIVE_AGENCY,
        StrideAICategory.AUDIT_TRAIL_GAPS,
    ],
    "model_provider": [
        StrideAICategory.MODEL_EXTRACTION,
        StrideAICategory.PROMPT_INJECTION,
        StrideAICategory.UNBOUNDED_CONSUMPTION,
    ],
    "database": [
        StrideAICategory.DATA_EXFILTRATION,
        StrideAICategory.DATA_POISONING,
    ],
    "cloud_service": [
        StrideAICategory.IDENTITY_SPOOFING,
        StrideAICategory.DATA_EXFILTRATION,
    ],
    "mcp_server": [
        StrideAICategory.TOOL_ABUSE,
        StrideAICategory.EXCESSIVE_AGENCY,
        StrideAICategory.DATA_EXFILTRATION,
    ],
    "tool": [
        StrideAICategory.TOOL_ABUSE,
        StrideAICategory.EXCESSIVE_AGENCY,
    ],
    "trigger": [
        StrideAICategory.IDENTITY_SPOOFING,
    ],
    "api_service": [
        StrideAICategory.IDENTITY_SPOOFING,
        StrideAICategory.RESOURCE_EXHAUSTION,
    ],
    "memory": [
        StrideAICategory.CONTEXT_MANIPULATION,
        StrideAICategory.DATA_EXFILTRATION,
    ],
    "vector_store": [
        StrideAICategory.DATA_POISONING,
        StrideAICategory.DATA_EXFILTRATION,
    ],
}


# ============================================================
# STRIDE-AI → Compliance framework IDs
# ============================================================

STRIDE_COMPLIANCE_MAP: dict[StrideAICategory, dict[str, list[str]]] = {
    # Spoofing
    StrideAICategory.MODEL_IMPERSONATION: {
        "owasp_llm": ["LLM01"],
        "mitre_atlas": ["AML.T0015"],
        "nist_ai_rmf": ["MANAGE-1"],
        "cwe": ["CWE-290"],
    },
    StrideAICategory.IDENTITY_SPOOFING: {
        "owasp_llm": [],
        "mitre_atlas": ["AML.T0015"],
        "nist_ai_rmf": ["MANAGE-1"],
        "cwe": ["CWE-287", "CWE-290"],
    },
    # Tampering
    StrideAICategory.PROMPT_INJECTION: {
        "owasp_llm": ["LLM01"],
        "mitre_atlas": ["AML.T0051", "AML.T0043"],
        "nist_ai_rmf": ["MANAGE-2", "MAP-1"],
        "cwe": ["CWE-77", "CWE-94"],
    },
    StrideAICategory.DATA_POISONING: {
        "owasp_llm": ["LLM04", "LLM08"],
        "mitre_atlas": ["AML.T0020"],
        "nist_ai_rmf": ["MANAGE-2", "MEASURE-2"],
        "cwe": ["CWE-20", "CWE-1188"],
    },
    StrideAICategory.MODEL_MANIPULATION: {
        "owasp_llm": ["LLM03", "LLM04"],
        "mitre_atlas": ["AML.T0018", "AML.T0019"],
        "nist_ai_rmf": ["GOVERN-1", "MAP-3"],
        "cwe": ["CWE-494", "CWE-829"],
    },
    StrideAICategory.CONTEXT_MANIPULATION: {
        "owasp_llm": ["LLM05", "LLM09"],
        "mitre_atlas": ["AML.T0043"],
        "nist_ai_rmf": ["MANAGE-2"],
        "cwe": ["CWE-20"],
    },
    # Repudiation
    StrideAICategory.AUDIT_TRAIL_GAPS: {
        "owasp_llm": [],
        "mitre_atlas": [],
        "nist_ai_rmf": ["GOVERN-1", "MEASURE-1"],
        "cwe": ["CWE-778"],
    },
    StrideAICategory.ATTRIBUTION_FAILURES: {
        "owasp_llm": ["LLM09"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["GOVERN-1", "MEASURE-1"],
        "cwe": ["CWE-345"],
    },
    # Information Disclosure
    StrideAICategory.SYSTEM_PROMPT_LEAKAGE: {
        "owasp_llm": ["LLM07"],
        "mitre_atlas": ["AML.T0024"],
        "nist_ai_rmf": ["MANAGE-3"],
        "cwe": ["CWE-200", "CWE-497"],
    },
    StrideAICategory.DATA_EXFILTRATION: {
        "owasp_llm": ["LLM02", "LLM07"],
        "mitre_atlas": ["AML.T0024", "AML.T0025"],
        "nist_ai_rmf": ["MANAGE-3", "MANAGE-4"],
        "cwe": ["CWE-200", "CWE-532"],
    },
    StrideAICategory.MODEL_EXTRACTION: {
        "owasp_llm": [],
        "mitre_atlas": ["AML.T0024"],
        "nist_ai_rmf": ["MANAGE-3"],
        "cwe": ["CWE-200"],
    },
    # Denial of Service
    StrideAICategory.RESOURCE_EXHAUSTION: {
        "owasp_llm": ["LLM10"],
        "mitre_atlas": ["AML.T0029"],
        "nist_ai_rmf": ["MANAGE-1"],
        "cwe": ["CWE-400", "CWE-770"],
    },
    StrideAICategory.UNBOUNDED_CONSUMPTION: {
        "owasp_llm": ["LLM10"],
        "mitre_atlas": ["AML.T0029"],
        "nist_ai_rmf": ["MANAGE-1", "MEASURE-3"],
        "cwe": ["CWE-400", "CWE-770"],
    },
    # Elevation of Privilege
    StrideAICategory.JAILBREAK: {
        "owasp_llm": ["LLM01"],
        "mitre_atlas": ["AML.T0051"],
        "nist_ai_rmf": ["MANAGE-2"],
        "cwe": ["CWE-284"],
    },
    StrideAICategory.EXCESSIVE_AGENCY: {
        "owasp_llm": ["LLM06"],
        "mitre_atlas": ["AML.T0040"],
        "nist_ai_rmf": ["GOVERN-2", "MANAGE-2"],
        "cwe": ["CWE-250", "CWE-269"],
    },
    StrideAICategory.TOOL_ABUSE: {
        "owasp_llm": ["LLM06"],
        "mitre_atlas": ["AML.T0040"],
        "nist_ai_rmf": ["MANAGE-2"],
        "cwe": ["CWE-250", "CWE-862"],
    },
}


# ============================================================
# Data classification signal patterns
# ============================================================

PII_INDICATORS: list[str] = [
    "pii", "ssn", "social_security", "date_of_birth", "passport",
    "driver_license", "personal_data", "gdpr", "personal_information",
    "email_address", "phone_number", "home_address",
]

FINANCIAL_INDICATORS: list[str] = [
    "payment", "credit_card", "bank", "financial", "billing",
    "transaction", "account_number", "routing_number", "pci",
    "stripe", "payment_processor",
]

HEALTH_INDICATORS: list[str] = [
    "health", "medical", "hipaa", "patient", "diagnosis",
    "prescription", "clinical", "ehr", "electronic_health",
    "phi", "protected_health",
]

# Auth mechanisms that suggest confidential data handling
CONFIDENTIAL_AUTH_SIGNALS: set[str] = {
    "jwt", "oauth", "azure_ad", "gcp_iam", "password_hashing",
    "encryption",
}

# Databases that typically store user/sensitive data
CONFIDENTIAL_DB_SIGNALS: set[str] = {
    "postgresql", "mongodb", "mysql", "cosmos_db", "sql_database",
    "firestore",
}

# Cloud services indicating sensitive data management
CONFIDENTIAL_CLOUD_SIGNALS: set[str] = {
    "key_vault", "secrets_manager", "secret_manager",
    "ssm_parameter_store",
}


# ============================================================
# Default severity and likelihood for topology-inferred threats
# ============================================================

# Default severity by STRIDE-AI category for theoretical (unconfirmed) threats
DEFAULT_THREAT_SEVERITY: dict[StrideAICategory, str] = {
    StrideAICategory.MODEL_IMPERSONATION: "medium",
    StrideAICategory.IDENTITY_SPOOFING: "medium",
    StrideAICategory.PROMPT_INJECTION: "high",
    StrideAICategory.DATA_POISONING: "high",
    StrideAICategory.MODEL_MANIPULATION: "high",
    StrideAICategory.CONTEXT_MANIPULATION: "medium",
    StrideAICategory.AUDIT_TRAIL_GAPS: "low",
    StrideAICategory.ATTRIBUTION_FAILURES: "low",
    StrideAICategory.SYSTEM_PROMPT_LEAKAGE: "medium",
    StrideAICategory.DATA_EXFILTRATION: "high",
    StrideAICategory.MODEL_EXTRACTION: "medium",
    StrideAICategory.RESOURCE_EXHAUSTION: "medium",
    StrideAICategory.UNBOUNDED_CONSUMPTION: "medium",
    StrideAICategory.JAILBREAK: "high",
    StrideAICategory.EXCESSIVE_AGENCY: "high",
    StrideAICategory.TOOL_ABUSE: "high",
}

# Default likelihood by STRIDE-AI category (theoretical, before evidence)
DEFAULT_THREAT_LIKELIHOOD: dict[StrideAICategory, float] = {
    StrideAICategory.MODEL_IMPERSONATION: 0.3,
    StrideAICategory.IDENTITY_SPOOFING: 0.3,
    StrideAICategory.PROMPT_INJECTION: 0.7,
    StrideAICategory.DATA_POISONING: 0.4,
    StrideAICategory.MODEL_MANIPULATION: 0.3,
    StrideAICategory.CONTEXT_MANIPULATION: 0.5,
    StrideAICategory.AUDIT_TRAIL_GAPS: 0.6,
    StrideAICategory.ATTRIBUTION_FAILURES: 0.5,
    StrideAICategory.SYSTEM_PROMPT_LEAKAGE: 0.6,
    StrideAICategory.DATA_EXFILTRATION: 0.5,
    StrideAICategory.MODEL_EXTRACTION: 0.3,
    StrideAICategory.RESOURCE_EXHAUSTION: 0.4,
    StrideAICategory.UNBOUNDED_CONSUMPTION: 0.4,
    StrideAICategory.JAILBREAK: 0.6,
    StrideAICategory.EXCESSIVE_AGENCY: 0.5,
    StrideAICategory.TOOL_ABUSE: 0.5,
}

# Default impact by STRIDE-AI category
DEFAULT_THREAT_IMPACT: dict[StrideAICategory, float] = {
    StrideAICategory.MODEL_IMPERSONATION: 0.6,
    StrideAICategory.IDENTITY_SPOOFING: 0.7,
    StrideAICategory.PROMPT_INJECTION: 0.8,
    StrideAICategory.DATA_POISONING: 0.8,
    StrideAICategory.MODEL_MANIPULATION: 0.9,
    StrideAICategory.CONTEXT_MANIPULATION: 0.5,
    StrideAICategory.AUDIT_TRAIL_GAPS: 0.3,
    StrideAICategory.ATTRIBUTION_FAILURES: 0.3,
    StrideAICategory.SYSTEM_PROMPT_LEAKAGE: 0.6,
    StrideAICategory.DATA_EXFILTRATION: 0.9,
    StrideAICategory.MODEL_EXTRACTION: 0.7,
    StrideAICategory.RESOURCE_EXHAUSTION: 0.5,
    StrideAICategory.UNBOUNDED_CONSUMPTION: 0.5,
    StrideAICategory.JAILBREAK: 0.8,
    StrideAICategory.EXCESSIVE_AGENCY: 0.8,
    StrideAICategory.TOOL_ABUSE: 0.8,
}


# Posture multipliers for risk calculation
POSTURE_MULTIPLIERS: dict[str, float] = {
    "local": 0.4,
    "internal": 0.7,
    "internet_facing": 1.0,
    "unknown": 0.85,
}


# Severity string to numeric for comparisons
SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


# Risk score → risk level mapping
def risk_level_from_score(score: float) -> str:
    """Map a 0-1 risk score to a risk level string."""
    if score >= 0.75:
        return "critical"
    if score >= 0.50:
        return "high"
    if score >= 0.30:
        return "medium"
    if score >= 0.10:
        return "low"
    return "safe"
