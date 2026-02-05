"""Core type definitions for MASS.

This module defines the canonical types used throughout the MASS platform,
including enums for risk levels, severity, scan status, component types,
and attack categories aligned with OWASP LLM Top 10.
"""

from enum import Enum


class RiskLevel(str, Enum):
    """Risk level classification for deployments and findings.

    Risk levels indicate the overall security posture and urgency
    of remediation required.
    """

    CRITICAL = "critical"  # Immediate action required, active exploitation possible
    HIGH = "high"  # Significant risk, should be addressed promptly
    MEDIUM = "medium"  # Moderate risk, plan remediation
    LOW = "low"  # Minor risk, address when convenient
    INFO = "info"  # Informational, no immediate risk
    SAFE = "safe"  # No risk detected, secure configuration


class Severity(str, Enum):
    """Finding severity classification.

    Severity indicates the potential impact of a vulnerability
    if exploited.
    """

    CRITICAL = "critical"  # Complete system compromise possible
    HIGH = "high"  # Significant data breach or system impact
    MEDIUM = "medium"  # Limited impact, specific conditions required
    LOW = "low"  # Minimal impact, difficult to exploit
    INFO = "info"  # Informational finding, no direct impact


class ConfidenceLevel(str, Enum):
    """Finding confidence level based on detection method.

    Indicates how the finding was detected and whether it has been
    validated through actual model interaction.
    """

    PREDICTED = "predicted"  # Topology-based risk assessment (not validated)
    STATIC_MATCH = "static_match"  # Regex pattern matched in source code (unvalidated)
    HEURISTIC = "heuristic"  # Pattern match with supporting contextual signals
    CONFIRMED = "confirmed"  # Validated via model interaction (prompt/response)


class ScanStatus(str, Enum):
    """Scan execution status.

    Tracks the lifecycle of a security scan from creation
    to completion.
    """

    PENDING = "pending"  # Scan created but not started
    QUEUED = "queued"  # Scan waiting in job queue
    RUNNING = "running"  # Scan actively executing
    COMPLETED = "completed"  # Scan finished successfully
    FAILED = "failed"  # Scan encountered an error
    CANCELLED = "cancelled"  # Scan cancelled by user


class ComponentType(str, Enum):
    """Deployment component types.

    Categorizes the different parts of an AI deployment that
    can be analyzed for security vulnerabilities.
    """

    MODEL = "model"  # AI/ML model (local or API)
    CONTEXT = "context"  # System prompts, instructions, personas
    MCP_SERVER = "mcp_server"  # Model Context Protocol tool servers
    SKILL = "skill"  # Agent skills and capabilities
    KNOWLEDGE = "knowledge"  # RAG knowledge bases, vector stores
    CODE = "code"  # Application code hosting the AI
    CONFIG = "config"  # Configuration files (YAML, JSON, env)
    INFRASTRUCTURE = "infrastructure"  # Docker, K8s, cloud resources
    WORKFLOW = "workflow"  # Agentic workflows (LangGraph, CrewAI, etc.)
    MEMORY = "memory"  # Conversation history, state management
    GUARDRAILS = "guardrails"  # Safety filters and content moderation


class AttackCategory(str, Enum):
    """Attack and vulnerability categories.

    Aligned with OWASP LLM Top 10 2025 and extended with
    additional categories for comprehensive coverage.

    See: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    """

    # OWASP LLM Top 10 2025
    PROMPT_INJECTION = "prompt_injection"  # LLM01: Direct and indirect injection
    SENSITIVE_INFO = "sensitive_info"  # LLM02: Sensitive information disclosure
    SUPPLY_CHAIN = "supply_chain"  # LLM03: Supply chain vulnerabilities
    DATA_MODEL_POISONING = "data_model_poisoning"  # LLM04: Data and model poisoning
    IMPROPER_OUTPUT = "improper_output"  # LLM05: Improper output handling
    EXCESSIVE_AGENCY = "excessive_agency"  # LLM06: Excessive agency
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"  # LLM07: System prompt leakage
    VECTOR_EMBEDDING = "vector_embedding"  # LLM08: Vector and embedding weaknesses
    MISINFORMATION = "misinformation"  # LLM09: Misinformation
    UNBOUNDED_CONSUMPTION = "unbounded_consumption"  # LLM10: Unbounded consumption

    # Extended categories
    JAILBREAK = "jailbreak"  # Bypassing safety guardrails
    DATA_LEAKAGE = "data_leakage"  # Unintended data exposure
    HALLUCINATION = "hallucination"  # Factually incorrect outputs
    BIAS = "bias"  # Discriminatory or biased outputs
    TOXICITY = "toxicity"  # Harmful, offensive, or inappropriate content
    SECRETS_EXPOSURE = "secrets_exposure"  # API keys, credentials in code/config
    INSECURE_PLUGIN = "insecure_plugin"  # Vulnerable MCP servers or tools
    MODEL_THEFT = "model_theft"  # Model extraction attacks
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Gaining unauthorized access
    DENIAL_OF_SERVICE = "denial_of_service"  # Resource exhaustion attacks


class FrameworkType(str, Enum):
    """Compliance framework types.

    Supported compliance and security frameworks for assessment.
    """

    OWASP_LLM = "owasp_llm"  # OWASP LLM Top 10
    OWASP_API = "owasp_api"  # OWASP API Top 10
    MITRE_ATLAS = "mitre_atlas"  # MITRE ATLAS
    NIST_AI_RMF = "nist_ai_rmf"  # NIST AI Risk Management Framework
    EU_AI_ACT = "eu_ai_act"  # EU AI Act
    GDPR = "gdpr"  # General Data Protection Regulation
    SOC2 = "soc2"  # SOC 2 Type II
    ISO_27001 = "iso_27001"  # ISO/IEC 27001
    CWE = "cwe"  # Common Weakness Enumeration


class AgenticFramework(str, Enum):
    """Supported agentic AI frameworks.

    Frameworks that MASS can analyze for workflow visualization
    and security assessment.
    """

    LANGCHAIN = "langchain"  # LangChain
    LANGGRAPH = "langgraph"  # LangGraph
    CREWAI = "crewai"  # CrewAI
    AUTOGEN = "autogen"  # Microsoft AutoGen
    OPENAI_AGENTS = "openai_agents"  # OpenAI Agents SDK
    SEMANTIC_KERNEL = "semantic_kernel"  # Microsoft Semantic Kernel
    HAYSTACK = "haystack"  # deepset Haystack
    LLAMAINDEX = "llamaindex"  # LlamaIndex
    CUSTOM = "custom"  # Custom/unknown framework


class ModelProvider(str, Enum):
    """Model provider types.

    Supported model providers for API-based interrogation.
    """

    OPENAI = "openai"  # OpenAI (GPT-4, etc.)
    ANTHROPIC = "anthropic"  # Anthropic (Claude)
    GOOGLE = "google"  # Google (Gemini)
    XAI = "xai"  # xAI (Grok)
    AZURE_OPENAI = "azure_openai"  # Azure OpenAI Service
    AWS_BEDROCK = "aws_bedrock"  # AWS Bedrock
    OLLAMA = "ollama"  # Ollama (local)
    HUGGINGFACE = "huggingface"  # HuggingFace Hub
    LOCAL = "local"  # Local model (llama.cpp, transformers)
    CUSTOM = "custom"  # Custom API endpoint
