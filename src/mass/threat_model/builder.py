"""Progressive AI threat model builder.

Accumulates data from each scan phase (discovery, static analysis,
interrogation, judge verdict) and produces a complete AIThreatModel.

Thread-safe: each scan gets its own builder instance. No LLM required —
all mapping and risk calculation is purely algorithmic.
"""

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from mass.threat_model.types import (
    AIThreatModel,
    DataClassification,
    DataFlowAnnotation,
    RiskMatrixEntry,
    StrideAICategory,
    StrideAIThreat,
    ThreatModelPhase,
    TrustBoundary,
    max_classification,
)
from mass.threat_model.mappings import (
    ATTACK_CATEGORY_TO_STRIDE,
    ATTACK_VECTOR_TO_STRIDE,
    CONFIDENTIAL_AUTH_SIGNALS,
    CONFIDENTIAL_CLOUD_SIGNALS,
    CONFIDENTIAL_DB_SIGNALS,
    DEFAULT_THREAT_IMPACT,
    DEFAULT_THREAT_LIKELIHOOD,
    DEFAULT_THREAT_SEVERITY,
    EDGE_TYPE_THREATS,
    FINANCIAL_INDICATORS,
    HEALTH_INDICATORS,
    NODE_TYPE_THREATS,
    PII_INDICATORS,
    POSTURE_MULTIPLIERS,
    SEVERITY_ORDER,
    STRIDE_COMPLIANCE_MAP,
    risk_level_from_score,
)

logger = logging.getLogger(__name__)


# Trust boundary zone classification
_EXTERNAL_ZONE = {"mcp_server", "api_service", "tool", "trigger"}
_MODEL_ZONE = {"ai_agent", "model_provider"}
_DATA_ZONE = {"database", "vector_store", "memory"}
_CLOUD_ZONE = {"cloud_service"}

_ZONE_MAP = {
    "external": _EXTERNAL_ZONE,
    "model": _MODEL_ZONE,
    "data": _DATA_ZONE,
    "cloud": _CLOUD_ZONE,
}

# Zone trust ordering (lower = less trusted)
_ZONE_TRUST_ORDER = {
    "external": 0,
    "cloud": 1,
    "data": 2,
    "model": 3,
}


def _make_id(prefix: str = "t") -> str:
    return f"{prefix}_{uuid4().hex[:8]}"


def _node_zone(node_type: str) -> str:
    """Classify a topology node type into a trust zone."""
    for zone_name, zone_types in _ZONE_MAP.items():
        if node_type in zone_types:
            return zone_name
    return "external"  # default to least trusted


class ThreatModelBuilder:
    """Progressively builds an AI-specific threat model across scan phases.

    Usage:
        builder = ThreatModelBuilder("my-deployment")
        builder.ingest_discovery(environment, topology, attack_surface, posture)
        builder.ingest_findings(findings)
        builder.ingest_interrogation(risk_score, findings)
        builder.ingest_verdict(verdict)
        model = builder.build()
    """

    def __init__(self, deployment_name: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._model = AIThreatModel(
            name=f"STRIDE-AI Threat Model — {deployment_name}",
            deployment_name=deployment_name,
            created_at=now,
            last_updated_at=now,
        )
        self._threat_counter = 0
        self._existing_stride_threats: dict[StrideAICategory, StrideAIThreat] = {}
        self._posture = "unknown"

    # ================================================================
    # Phase 1: Discovery
    # ================================================================

    def ingest_discovery(
        self,
        environment: dict[str, Any],
        topology: dict[str, Any],
        attack_surface: dict[str, Any] | None,
        deployment_posture: str,
    ) -> None:
        """Phase 1: Build initial model from discovery data."""
        self._posture = deployment_posture
        self._model.deployment_posture = deployment_posture
        self._model.last_updated_at = datetime.now(timezone.utc).isoformat()

        # Extract assets from topology nodes
        nodes = topology.get("nodes", [])
        edges = topology.get("edges", [])
        self._model.assets = list(nodes)

        # Infer trust boundaries
        self._model.trust_boundaries = self._infer_trust_boundaries(
            nodes, edges
        )

        # Create data flow annotations from topology edges
        self._model.data_flows = self._annotate_data_flows(
            nodes, edges, self._model.trust_boundaries
        )

        # Infer data classification from environment
        classification, signals = self._infer_data_classification(
            environment, topology
        )
        self._model.data_classification = classification
        self._model.data_classification_signals = signals

        # Generate threats from topology nodes
        self._generate_node_threats(nodes)

        # Generate threats from topology edges crossing trust boundaries
        self._generate_edge_threats(edges, nodes)

        # Generate threats from attack vectors if provided
        if attack_surface:
            self._generate_attack_surface_threats(attack_surface)

        self._model.phases_completed.append(ThreatModelPhase.DISCOVERY.value)

    # ================================================================
    # Phase 1b: Architecture Map (from AI code analysis)
    # ================================================================

    def ingest_architecture_map(
        self, architecture_map: dict[str, Any]
    ) -> None:
        """Enrich threat model with AI-analyzed code architecture.

        Generates threats from:
        - Tool capabilities (command_execution → EXCESSIVE_AGENCY)
        - Missing safety measures (no input validation → PROMPT_INJECTION)
        - Model connections with tools enabled (tool injection surface)
        - Unvalidated tools (TOOL_ABUSE)
        """
        self._model.last_updated_at = datetime.now(timezone.utc).isoformat()

        # ── Tool capability threats ──
        for tool in architecture_map.get("tool_definitions", []):
            capabilities = tool.get("capabilities", [])
            tool_name = tool.get("name", "unknown")
            validation = tool.get("validation")

            # High-risk capabilities
            if "command_execution" in capabilities:
                self._add_arch_threat(
                    StrideAICategory.EXCESSIVE_AGENCY,
                    f"Excessive Agency: Tool '{tool_name}' has command execution",
                    f"Tool '{tool_name}' at {tool.get('location', '?')} can execute "
                    f"system commands. If model input is not carefully validated, an "
                    f"attacker could achieve arbitrary code execution via prompt injection.",
                    severity="critical",
                    likelihood=0.7,
                    components=[tool_name],
                )

            if "file_system" in capabilities:
                self._add_arch_threat(
                    StrideAICategory.DATA_EXFILTRATION,
                    f"Data Exfiltration: Tool '{tool_name}' has file system access",
                    f"Tool '{tool_name}' can read/write the file system. An attacker "
                    f"could exfiltrate sensitive data or plant malicious files.",
                    severity="high",
                    likelihood=0.6,
                    components=[tool_name],
                )

            if "network" in capabilities:
                self._add_arch_threat(
                    StrideAICategory.DATA_EXFILTRATION,
                    f"Data Exfiltration: Tool '{tool_name}' has network access",
                    f"Tool '{tool_name}' can make network requests. An attacker could "
                    f"exfiltrate data to external servers via crafted tool calls.",
                    severity="high",
                    likelihood=0.5,
                    components=[tool_name],
                )

            if "database" in capabilities:
                self._add_arch_threat(
                    StrideAICategory.DATA_EXFILTRATION,
                    f"Data Exfiltration: Tool '{tool_name}' has database access",
                    f"Tool '{tool_name}' can query databases. An attacker could "
                    f"extract sensitive records via prompt injection.",
                    severity="high",
                    likelihood=0.5,
                    components=[tool_name],
                )

            # Missing validation on any tool
            if not validation:
                self._add_arch_threat(
                    StrideAICategory.TOOL_ABUSE,
                    f"Tool Abuse: '{tool_name}' lacks input validation",
                    f"Tool '{tool_name}' has no detected input validation. "
                    f"Unvalidated tool inputs enable injection attacks.",
                    severity="medium",
                    likelihood=0.6,
                    components=[tool_name],
                )

        # ── Model connection threats ──
        for mc in architecture_map.get("model_connections", []):
            provider = mc.get("provider", "unknown")
            model_name = mc.get("model_name", "")
            has_tools = mc.get("has_tools", False)

            if has_tools:
                self._add_arch_threat(
                    StrideAICategory.PROMPT_INJECTION,
                    f"Prompt Injection: {provider} model with tools enabled",
                    f"Model connection to {provider}"
                    f"{(' (' + model_name + ')') if model_name else ''} "
                    f"at {mc.get('call_location', '?')} has tool calling enabled. "
                    f"Adversarial input could manipulate tool selection and parameters.",
                    severity="high",
                    likelihood=0.6,
                    components=[model_name or provider],
                )

            if mc.get("system_prompt_source") == "inline":
                self._add_arch_threat(
                    StrideAICategory.SYSTEM_PROMPT_LEAKAGE,
                    f"System Prompt Leakage: inline prompt in source code",
                    f"System prompt for {provider} model is hardcoded inline "
                    f"at {mc.get('call_location', '?')}. Inline prompts are more "
                    f"susceptible to extraction via prompt injection.",
                    severity="medium",
                    likelihood=0.5,
                    components=[model_name or provider],
                )

        # ── Missing safety measures ──
        safety_types = {
            sm.get("type") for sm in architecture_map.get("safety_measures", [])
        }

        if "input_validation" not in safety_types:
            self._add_arch_threat(
                StrideAICategory.PROMPT_INJECTION,
                "Insufficient Guardrails: No input validation detected",
                "No input validation or sanitization was found in the codebase. "
                "User input flows directly to models without filtering, enabling "
                "prompt injection attacks.",
                severity="high",
                likelihood=0.7,
                components=[],
            )

        if "output_filtering" not in safety_types:
            self._add_arch_threat(
                StrideAICategory.DATA_EXFILTRATION,
                "Insufficient Guardrails: No output filtering detected",
                "No output filtering or content moderation was found. Model "
                "responses are returned directly without checking for sensitive "
                "data leakage or harmful content.",
                severity="medium",
                likelihood=0.5,
                components=[],
            )

        if "rate_limiting" not in safety_types:
            self._add_arch_threat(
                StrideAICategory.RESOURCE_EXHAUSTION,
                "Resource Exhaustion: No rate limiting detected",
                "No rate limiting was found on model-facing endpoints. An "
                "attacker could exhaust API quotas or compute resources.",
                severity="medium",
                likelihood=0.4,
                components=[],
            )

        # ── Entry point threats ──
        for ep in architecture_map.get("entry_points", []):
            if not ep.get("authentication"):
                self._add_arch_threat(
                    StrideAICategory.IDENTITY_SPOOFING,
                    f"Identity Spoofing: Unauthenticated {ep.get('type', 'endpoint')}",
                    f"Entry point at {ep.get('location', '?')} accepts "
                    f"{ep.get('accepts', 'input')} without authentication. "
                    f"Any user can interact with the AI system.",
                    severity="medium",
                    likelihood=0.6,
                    components=[ep.get("location", "")],
                )

        logger.info(
            "Architecture map ingested: %d tools, %d models, %d safety measures → %d threats",
            len(architecture_map.get("tool_definitions", [])),
            len(architecture_map.get("model_connections", [])),
            len(architecture_map.get("safety_measures", [])),
            len(self._model.threats),
        )

    def ingest_questionnaire(
        self, questionnaire: dict[str, Any]
    ) -> None:
        """Enrich threat model with user-provided risk context.

        Adjusts threat severity based on deployment environment,
        data sensitivity, and compliance requirements.
        """
        self._model.last_updated_at = datetime.now(timezone.utc).isoformat()

        is_public = questionnaire.get("is_public_facing", False)
        env = questionnaire.get("deployment_environment")
        handles_pii = questionnaire.get("handles_pii", False)
        has_payment = questionnaire.get("has_payment_data", False)
        sensitivity = questionnaire.get("data_sensitivity")
        frameworks = questionnaire.get("compliance_frameworks") or []

        # ── Public-facing + production: elevate network attack threats ──
        if is_public and env == "production":
            for cat in (
                StrideAICategory.IDENTITY_SPOOFING,
                StrideAICategory.RESOURCE_EXHAUSTION,
            ):
                existing = self._existing_stride_threats.get(cat)
                if existing:
                    if SEVERITY_ORDER.get(existing.severity, 0) < SEVERITY_ORDER.get("high", 0):
                        existing.severity = "high"
                    existing.likelihood = min(existing.likelihood + 0.2, 1.0)
                else:
                    self._add_arch_threat(
                        cat,
                        f"Elevated Risk: Public-facing production system",
                        f"This target is public-facing in production, increasing exposure "
                        f"to {cat.value.replace('_', ' ')} attacks.",
                        severity="high",
                        likelihood=0.7,
                        components=[],
                    )

        # ── PII handling: elevate data exfiltration / prompt leakage ──
        if handles_pii:
            for cat in (
                StrideAICategory.DATA_EXFILTRATION,
                StrideAICategory.SYSTEM_PROMPT_LEAKAGE,
            ):
                existing = self._existing_stride_threats.get(cat)
                if existing:
                    if SEVERITY_ORDER.get(existing.severity, 0) < SEVERITY_ORDER.get("high", 0):
                        existing.severity = "high"
                    existing.likelihood = min(existing.likelihood + 0.15, 1.0)
                else:
                    self._add_arch_threat(
                        cat,
                        f"PII Exposure: {cat.value.replace('_', ' ').title()} risk",
                        f"This target handles PII. A {cat.value.replace('_', ' ')} "
                        f"vulnerability could result in personal data breach with "
                        f"regulatory notification requirements.",
                        severity="high",
                        likelihood=0.6,
                        components=[],
                    )

        # ── Payment data: critical data exfiltration ──
        if has_payment:
            cat = StrideAICategory.DATA_EXFILTRATION
            existing = self._existing_stride_threats.get(cat)
            if existing:
                existing.severity = "critical"
                existing.likelihood = min(existing.likelihood + 0.2, 1.0)
            else:
                self._add_arch_threat(
                    cat,
                    "Critical Data: Payment data exfiltration risk",
                    "This target processes payment data. Data exfiltration could "
                    "result in financial fraud and PCI-DSS compliance violations.",
                    severity="critical",
                    likelihood=0.6,
                    components=[],
                )

        # ── Regulated data: add compliance-aware threats ──
        if sensitivity == "regulated" or (frameworks and "none" not in frameworks):
            active_frameworks = [f for f in frameworks if f != "none"]
            if not active_frameworks and sensitivity == "regulated":
                active_frameworks = ["unspecified"]

            if active_frameworks:
                cat = StrideAICategory.AUDIT_TRAIL_GAPS
                existing = self._existing_stride_threats.get(cat)
                if existing:
                    if SEVERITY_ORDER.get(existing.severity, 0) < SEVERITY_ORDER.get("high", 0):
                        existing.severity = "high"
                else:
                    self._add_arch_threat(
                        cat,
                        f"Compliance: Audit trail requirements ({', '.join(active_frameworks)})",
                        f"This target operates under {', '.join(f.upper() for f in active_frameworks)} "
                        f"compliance. Insufficient audit logging of AI interactions could "
                        f"violate regulatory requirements.",
                        severity="high",
                        likelihood=0.5,
                        components=[],
                    )

        logger.info(
            "Questionnaire ingested: public=%s env=%s pii=%s payment=%s -> %d threats",
            is_public, env, handles_pii, has_payment,
            len(self._model.threats),
        )

    def _add_arch_threat(
        self,
        stride_cat: StrideAICategory,
        title: str,
        description: str,
        severity: str,
        likelihood: float,
        components: list[str],
    ) -> None:
        """Add or enrich a threat from architecture analysis."""
        existing = self._existing_stride_threats.get(stride_cat)
        if existing:
            # Upgrade severity if worse
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(
                existing.severity, 0
            ):
                existing.severity = severity
            existing.likelihood = min(existing.likelihood + 0.1, 1.0)
            for comp in components:
                if comp and comp not in existing.affected_components:
                    existing.affected_components.append(comp)
            return

        compliance = self._get_compliance_ids(stride_cat)
        threat = self._create_threat(
            stride_category=stride_cat,
            title=title,
            description=description,
            severity=severity,
            likelihood=likelihood,
            impact=DEFAULT_THREAT_IMPACT.get(stride_cat, 0.5),
            phase=ThreatModelPhase.DISCOVERY,
            affected_components=[c for c in components if c],
            compliance=compliance,
        )
        self._model.threats.append(threat)
        self._existing_stride_threats[stride_cat] = threat

    # ================================================================
    # Phase 2: Static Analysis Findings
    # ================================================================

    def ingest_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> None:
        """Phase 2: Enrich with static analysis findings."""
        self._model.last_updated_at = datetime.now(timezone.utc).isoformat()

        for finding in findings:
            category = finding.get("category", "")
            stride_cat = self._finding_to_stride(finding)
            if stride_cat is None:
                continue

            severity = finding.get("severity", "medium")
            title = finding.get("title", "Unknown finding")
            finding_id = finding.get("id", "")

            # Check if we already have a threat for this STRIDE category
            existing = self._existing_stride_threats.get(stride_cat)
            if existing:
                # Upgrade severity if this finding is worse
                if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(
                    existing.severity, 0
                ):
                    existing.severity = severity
                # Increase likelihood based on evidence
                existing.likelihood = min(existing.likelihood + 0.1, 1.0)
                if finding_id:
                    existing.evidence_sources.append(finding_id)
                # Add component info
                comp_name = finding.get("component_name", "")
                if comp_name and comp_name not in existing.affected_components:
                    existing.affected_components.append(comp_name)
            else:
                # Create new threat from finding
                compliance = self._get_compliance_ids(stride_cat, category)
                threat = self._create_threat(
                    stride_category=stride_cat,
                    title=f"{stride_cat.value.replace('_', ' ').title()}: {title}",
                    description=finding.get("description", ""),
                    severity=severity,
                    likelihood=self._severity_to_likelihood(severity),
                    impact=DEFAULT_THREAT_IMPACT.get(stride_cat, 0.5),
                    phase=ThreatModelPhase.STATIC_ANALYSIS,
                    evidence_sources=[finding_id] if finding_id else [],
                    affected_components=[
                        finding.get("component_name", "")
                    ],
                    compliance=compliance,
                )
                self._model.threats.append(threat)
                self._existing_stride_threats[stride_cat] = threat

            # Update data classification if PII/credential findings appear
            self._update_classification_from_finding(finding)

        self._model.phases_completed.append(
            ThreatModelPhase.STATIC_ANALYSIS.value
        )

    # ================================================================
    # Phase 3: Interrogation
    # ================================================================

    def ingest_interrogation(
        self,
        risk_score: dict[str, Any] | None,
        findings: list[dict[str, Any]],
    ) -> None:
        """Phase 3: Enrich with dynamic testing results."""
        self._model.last_updated_at = datetime.now(timezone.utc).isoformat()

        # Mark threats as confirmed based on matching interrogation findings
        for finding in findings:
            stride_cat = self._finding_to_stride(finding)
            if stride_cat is None:
                continue

            existing = self._existing_stride_threats.get(stride_cat)
            if existing:
                existing.confirmed = True
                existing.likelihood = min(existing.likelihood + 0.2, 1.0)
                finding_id = finding.get("id", "")
                if finding_id:
                    existing.evidence_sources.append(finding_id)
            else:
                # New threat discovered only via interrogation
                severity = finding.get("severity", "medium")
                compliance = self._get_compliance_ids(
                    stride_cat, finding.get("category", "")
                )
                threat = self._create_threat(
                    stride_category=stride_cat,
                    title=f"Confirmed: {stride_cat.value.replace('_', ' ').title()}",
                    description=finding.get("description", ""),
                    severity=severity,
                    likelihood=self._severity_to_likelihood(severity) + 0.1,
                    impact=DEFAULT_THREAT_IMPACT.get(stride_cat, 0.5),
                    phase=ThreatModelPhase.INTERROGATION,
                    evidence_sources=[finding.get("id", "")],
                    compliance=compliance,
                    confirmed=True,
                )
                self._model.threats.append(threat)
                self._existing_stride_threats[stride_cat] = threat

        # Incorporate risk_score category breakdowns
        if risk_score:
            category_scores = risk_score.get("category_scores", {})
            for cat_name, score in category_scores.items():
                stride_cat = ATTACK_CATEGORY_TO_STRIDE.get(cat_name)
                if stride_cat and stride_cat in self._existing_stride_threats:
                    threat = self._existing_stride_threats[stride_cat]
                    # High category score → increase likelihood
                    if score > 50:
                        threat.likelihood = min(
                            threat.likelihood + 0.15, 1.0
                        )
                        threat.confirmed = True

        self._model.phases_completed.append(
            ThreatModelPhase.INTERROGATION.value
        )

    # ================================================================
    # Phase 4: Judge Verdict
    # ================================================================

    def ingest_verdict(
        self,
        verdict: dict[str, Any],
    ) -> None:
        """Phase 4: Integrate judge analysis."""
        self._model.last_updated_at = datetime.now(timezone.utc).isoformat()

        # Incorporate attack chains as multi-step threats
        attack_chains = verdict.get("attack_chains", [])
        for chain in attack_chains:
            chain_name = chain.get("name", "Attack Chain")
            risk_level = chain.get("risk_level", "high")
            description = chain.get("description", "")
            steps = chain.get("steps", [])

            # Determine STRIDE category from the chain
            stride_cat = StrideAICategory.DATA_EXFILTRATION
            desc_lower = description.lower()
            if "jailbreak" in desc_lower or "bypass" in desc_lower:
                stride_cat = StrideAICategory.JAILBREAK
            elif "prompt" in desc_lower or "injection" in desc_lower:
                stride_cat = StrideAICategory.PROMPT_INJECTION
            elif "tool" in desc_lower or "agency" in desc_lower:
                stride_cat = StrideAICategory.EXCESSIVE_AGENCY
            elif "exfiltrat" in desc_lower or "leak" in desc_lower:
                stride_cat = StrideAICategory.DATA_EXFILTRATION

            compliance = self._get_compliance_ids(stride_cat)
            threat = self._create_threat(
                stride_category=stride_cat,
                title=f"Attack Chain: {chain_name}",
                description=f"{description} Steps: {' → '.join(steps)}",
                severity=risk_level,
                likelihood=0.7 if risk_level in ("critical", "high") else 0.5,
                impact=0.9 if risk_level == "critical" else 0.7,
                phase=ThreatModelPhase.JUDGE_VERDICT,
                evidence_sources=[f"chain:{chain_name}"],
                compliance=compliance,
                confirmed=True,
            )
            self._model.threats.append(threat)

        # Apply severity adjustments from judge
        adjustments = verdict.get("severity_adjustments", [])
        for adj in adjustments:
            finding_title = adj.get("finding_title", "").lower()
            new_severity = adj.get("adjusted_severity", "")
            # Try to find matching threat
            for threat in self._model.threats:
                if finding_title in threat.title.lower():
                    if new_severity and SEVERITY_ORDER.get(
                        new_severity, 0
                    ) != SEVERITY_ORDER.get(threat.severity, 0):
                        threat.severity = new_severity

        # Add judge recommendations to mitigations
        recommendations = verdict.get("recommendations", [])
        for rec in recommendations:
            title = rec.get("title", "")
            description = rec.get("description", "")
            mitigation_text = f"{title}: {description}"
            # Find matching threats to attach mitigations
            for threat in self._model.threats:
                if not threat.mitigations or len(threat.mitigations) < 3:
                    threat.mitigations.append(mitigation_text)
                    break  # One recommendation per threat max

        self._model.phases_completed.append(
            ThreatModelPhase.JUDGE_VERDICT.value
        )

    # ================================================================
    # Build final model
    # ================================================================

    def build(self) -> AIThreatModel:
        """Finalize and return the complete threat model."""
        self._model.last_updated_at = datetime.now(timezone.utc).isoformat()

        # Calculate risk scores for all threats
        posture_mult = POSTURE_MULTIPLIERS.get(self._posture, 0.85)
        for threat in self._model.threats:
            threat.risk_score = threat.likelihood * threat.impact * posture_mult

        # Build risk matrix
        self._model.risk_matrix = [
            RiskMatrixEntry(
                threat_id=t.id,
                threat_title=t.title,
                likelihood=t.likelihood,
                impact=t.impact,
                risk_score=t.risk_score,
                severity=t.severity,
                stride_category=t.stride_category.value,
            )
            for t in self._model.threats
        ]

        # Compute summary statistics
        stride_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        for threat in self._model.threats:
            cat = threat.stride_category.value
            stride_counts[cat] = stride_counts.get(cat, 0) + 1
            sev = threat.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        self._model.threat_counts_by_stride = stride_counts
        self._model.threat_counts_by_severity = severity_counts

        # Sort top risks by risk_score descending
        sorted_threats = sorted(
            self._model.threats,
            key=lambda t: t.risk_score,
            reverse=True,
        )
        self._model.top_risks = [t.id for t in sorted_threats[:10]]

        # Overall risk level from max risk score
        max_score = max(
            (t.risk_score for t in self._model.threats), default=0.0
        )
        self._model.overall_risk_level = risk_level_from_score(max_score)

        # Aggregate compliance summary
        compliance: dict[str, set[str]] = {}
        for threat in self._model.threats:
            for fw_key, ids in [
                ("owasp_llm", threat.owasp_llm_ids),
                ("mitre_atlas", threat.mitre_atlas_ids),
                ("nist_ai_rmf", threat.nist_ai_rmf_ids),
                ("cwe", threat.cwe_ids),
            ]:
                if ids:
                    if fw_key not in compliance:
                        compliance[fw_key] = set()
                    compliance[fw_key].update(ids)

        self._model.compliance_summary = {
            k: sorted(v) for k, v in compliance.items()
        }

        # Aggregate and deduplicate mitigations
        self._model.recommended_mitigations = self._aggregate_mitigations()

        return self._model

    # ================================================================
    # Internal helpers
    # ================================================================

    def _create_threat(
        self,
        stride_category: StrideAICategory,
        title: str,
        description: str,
        severity: str,
        likelihood: float,
        impact: float,
        phase: ThreatModelPhase,
        evidence_sources: list[str] | None = None,
        affected_components: list[str] | None = None,
        compliance: dict[str, list[str]] | None = None,
        confirmed: bool = False,
    ) -> StrideAIThreat:
        """Create a new threat entry."""
        self._threat_counter += 1
        comp = compliance or {}
        return StrideAIThreat(
            id=f"SAT-{self._threat_counter:04d}",
            stride_category=stride_category,
            title=title,
            description=description,
            severity=severity,
            likelihood=min(likelihood, 1.0),
            impact=min(impact, 1.0),
            risk_score=0.0,  # Calculated in build()
            affected_components=[c for c in (affected_components or []) if c],
            evidence_phase=phase,
            evidence_sources=evidence_sources or [],
            owasp_llm_ids=comp.get("owasp_llm", []),
            mitre_atlas_ids=comp.get("mitre_atlas", []),
            nist_ai_rmf_ids=comp.get("nist_ai_rmf", []),
            cwe_ids=comp.get("cwe", []),
            confirmed=confirmed,
        )

    def _infer_trust_boundaries(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> list[TrustBoundary]:
        """Identify trust boundaries by grouping nodes into zones."""
        # Classify nodes into zones
        zone_nodes: dict[str, list[str]] = {
            z: [] for z in _ZONE_MAP
        }
        node_zones: dict[str, str] = {}

        for node in nodes:
            node_id = node.get("id", "")
            node_type = node.get("type", "")
            zone = _node_zone(node_type)
            zone_nodes[zone].append(node_id)
            node_zones[node_id] = zone

        # Find edges that cross zone boundaries
        boundaries: list[TrustBoundary] = []
        seen_pairs: set[tuple[str, str]] = set()

        for edge in edges:
            source_id = edge.get("source", "")
            target_id = edge.get("target", "")
            source_zone = node_zones.get(source_id, "external")
            target_zone = node_zones.get(target_id, "external")

            if source_zone != target_zone:
                pair = tuple(sorted([source_zone, target_zone]))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)

                    # More trusted zone is "inside"
                    if _ZONE_TRUST_ORDER.get(
                        pair[0], 0
                    ) > _ZONE_TRUST_ORDER.get(pair[1], 0):
                        inside_zone, outside_zone = pair[0], pair[1]
                    else:
                        inside_zone, outside_zone = pair[1], pair[0]

                    # Collect all crossing edges for this zone pair
                    crossing = [
                        e.get("id", "")
                        for e in edges
                        if (
                            node_zones.get(e.get("source", "")) in pair
                            and node_zones.get(e.get("target", "")) in pair
                            and node_zones.get(e.get("source", ""))
                            != node_zones.get(e.get("target", ""))
                        )
                    ]

                    boundaries.append(
                        TrustBoundary(
                            id=_make_id("tb"),
                            name=f"{outside_zone.title()} → {inside_zone.title()} Boundary",
                            description=(
                                f"Trust boundary between {outside_zone} zone "
                                f"and {inside_zone} zone"
                            ),
                            components_inside=zone_nodes.get(
                                inside_zone, []
                            ),
                            components_outside=zone_nodes.get(
                                outside_zone, []
                            ),
                            crossing_edges=crossing,
                        )
                    )

        return boundaries

    def _annotate_data_flows(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        trust_boundaries: list[TrustBoundary],
    ) -> list[DataFlowAnnotation]:
        """Create data flow annotations from topology edges."""
        # Build set of boundary-crossing edge IDs
        crossing_edge_ids: set[str] = set()
        for tb in trust_boundaries:
            crossing_edge_ids.update(tb.crossing_edges)

        # Data type inference from edge type
        edge_data_types = {
            "data_flow": ["application_data"],
            "auth": ["credentials", "tokens"],
            "tool_call": ["tool_parameters", "tool_results"],
            "api_call": ["request_data", "response_data"],
            "model_query": ["prompts", "completions"],
        }

        flows: list[DataFlowAnnotation] = []
        for edge in edges:
            edge_id = edge.get("id", "")
            edge_type = edge.get("edge_type", "data_flow")
            source = edge.get("source", "")
            target = edge.get("target", "")

            # Determine applicable threats for this edge type
            applicable = [
                cat.value
                for cat in EDGE_TYPE_THREATS.get(edge_type, [])
            ]

            flows.append(
                DataFlowAnnotation(
                    edge_id=edge_id,
                    source_node=source,
                    target_node=target,
                    data_types=edge_data_types.get(edge_type, []),
                    classification=self._model.data_classification,
                    crosses_trust_boundary=edge_id in crossing_edge_ids,
                    applicable_threats=applicable,
                )
            )

        return flows

    def _infer_data_classification(
        self,
        environment: dict[str, Any],
        topology: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
    ) -> tuple[DataClassification, list[str]]:
        """Infer data sensitivity from environment signals."""
        signals: list[str] = []
        classification = DataClassification.INTERNAL

        # Check auth mechanisms (may be list of strings or list of dicts)
        raw_auth = environment.get("auth_mechanisms", [])
        auth_mechs: set[str] = set()
        for a in raw_auth:
            if isinstance(a, dict):
                auth_mechs.add(a.get("type", ""))
                auth_mechs.add(a.get("name", ""))
            else:
                auth_mechs.add(str(a))
        auth_mechs.discard("")
        if auth_mechs & CONFIDENTIAL_AUTH_SIGNALS:
            signals.append(
                f"Auth mechanisms ({', '.join(auth_mechs & CONFIDENTIAL_AUTH_SIGNALS)}) "
                f"suggest confidential data handling"
            )
            classification = max_classification(
                classification, DataClassification.CONFIDENTIAL
            )

        # Check databases (may be list of strings or list of dicts)
        raw_dbs = environment.get("databases", [])
        databases: set[str] = set()
        for d in raw_dbs:
            if isinstance(d, dict):
                databases.add(d.get("type", ""))
                databases.add(d.get("name", ""))
            else:
                databases.add(str(d))
        databases.discard("")
        if databases & CONFIDENTIAL_DB_SIGNALS:
            signals.append(
                f"Persistent database ({', '.join(databases & CONFIDENTIAL_DB_SIGNALS)}) "
                f"suggests stored user data"
            )
            classification = max_classification(
                classification, DataClassification.CONFIDENTIAL
            )

        # Check cloud services for secrets management
        for svc in environment.get("cloud_services", []):
            svc_type = svc.get("service_type", "")
            if svc_type in CONFIDENTIAL_CLOUD_SIGNALS:
                signals.append(
                    f"Secrets management service ({svc_type}) indicates "
                    f"sensitive credential handling"
                )
                classification = max_classification(
                    classification, DataClassification.CONFIDENTIAL
                )

        # Check topology for vector stores
        for node in topology.get("nodes", []):
            if node.get("type") == "vector_store":
                signals.append(
                    "Vector store suggests knowledge base with "
                    "potentially sensitive data"
                )
                classification = max_classification(
                    classification, DataClassification.CONFIDENTIAL
                )
                break

        # Check findings for PII/financial/health indicators
        if findings:
            self._classify_from_findings(findings, signals)
            if any("PII" in s or "Restricted" in s for s in signals):
                classification = DataClassification.RESTRICTED

        # Internet-facing implies user data processing
        if self._posture == "internet_facing":
            signals.append(
                "Internet-facing deployment implies user data processing"
            )
            classification = max_classification(
                classification, DataClassification.CONFIDENTIAL
            )

        if not signals:
            signals.append(
                "No specific signals detected; defaulting to INTERNAL"
            )

        return classification, signals

    def _classify_from_findings(
        self,
        findings: list[dict[str, Any]],
        signals: list[str],
    ) -> None:
        """Check findings for data classification indicators."""
        for finding in findings:
            text = (
                finding.get("title", "")
                + " "
                + finding.get("description", "")
            ).lower()

            if any(ind in text for ind in PII_INDICATORS):
                signals.append(
                    f"PII indicator in finding: {finding.get('title', '')[:60]}"
                )
            if any(ind in text for ind in FINANCIAL_INDICATORS):
                signals.append(
                    f"Financial data indicator: {finding.get('title', '')[:60]}"
                )
            if any(ind in text for ind in HEALTH_INDICATORS):
                signals.append(
                    f"Health data indicator: {finding.get('title', '')[:60]}"
                )

    def _generate_node_threats(
        self, nodes: list[dict[str, Any]]
    ) -> None:
        """Generate threats from topology node types."""
        for node in nodes:
            node_type = node.get("type", "")
            node_name = node.get("name", "")
            node_id = node.get("id", "")

            inherent_threats = NODE_TYPE_THREATS.get(node_type, [])
            for stride_cat in inherent_threats:
                if stride_cat in self._existing_stride_threats:
                    # Already tracked — add this component
                    existing = self._existing_stride_threats[stride_cat]
                    if node_name and node_name not in existing.affected_components:
                        existing.affected_components.append(node_name)
                    continue

                compliance = self._get_compliance_ids(stride_cat)
                threat = self._create_threat(
                    stride_category=stride_cat,
                    title=(
                        f"{stride_cat.value.replace('_', ' ').title()} "
                        f"via {node_type.replace('_', ' ')}"
                    ),
                    description=(
                        f"The {node_type.replace('_', ' ')} component "
                        f"'{node_name}' is susceptible to "
                        f"{stride_cat.value.replace('_', ' ')}"
                    ),
                    severity=DEFAULT_THREAT_SEVERITY.get(stride_cat, "medium"),
                    likelihood=DEFAULT_THREAT_LIKELIHOOD.get(stride_cat, 0.5),
                    impact=DEFAULT_THREAT_IMPACT.get(stride_cat, 0.5),
                    phase=ThreatModelPhase.DISCOVERY,
                    affected_components=[node_name],
                    compliance=compliance,
                )
                self._model.threats.append(threat)
                self._existing_stride_threats[stride_cat] = threat

    def _generate_edge_threats(
        self,
        edges: list[dict[str, Any]],
        nodes: list[dict[str, Any]],
    ) -> None:
        """Generate threats from edges crossing trust boundaries."""
        node_map = {n.get("id", ""): n for n in nodes}
        node_zones = {
            n.get("id", ""): _node_zone(n.get("type", ""))
            for n in nodes
        }

        for edge in edges:
            source_id = edge.get("source", "")
            target_id = edge.get("target", "")
            edge_type = edge.get("edge_type", "")

            # Only generate additional threats for cross-boundary edges
            source_zone = node_zones.get(source_id, "external")
            target_zone = node_zones.get(target_id, "external")
            if source_zone == target_zone:
                continue

            applicable = EDGE_TYPE_THREATS.get(edge_type, [])
            source_name = node_map.get(source_id, {}).get("name", source_id)
            target_name = node_map.get(target_id, {}).get("name", target_id)

            for stride_cat in applicable:
                if stride_cat in self._existing_stride_threats:
                    existing = self._existing_stride_threats[stride_cat]
                    if edge.get("id"):
                        existing.data_flow_ids.append(edge["id"])
                    continue

                compliance = self._get_compliance_ids(stride_cat)
                threat = self._create_threat(
                    stride_category=stride_cat,
                    title=(
                        f"{stride_cat.value.replace('_', ' ').title()} "
                        f"across {source_zone}→{target_zone} boundary"
                    ),
                    description=(
                        f"Data flow from '{source_name}' to '{target_name}' "
                        f"crosses a trust boundary ({edge_type}), enabling "
                        f"{stride_cat.value.replace('_', ' ')}"
                    ),
                    severity=DEFAULT_THREAT_SEVERITY.get(stride_cat, "medium"),
                    likelihood=DEFAULT_THREAT_LIKELIHOOD.get(stride_cat, 0.5),
                    impact=DEFAULT_THREAT_IMPACT.get(stride_cat, 0.5),
                    phase=ThreatModelPhase.DISCOVERY,
                    affected_components=[source_name, target_name],
                    compliance=compliance,
                )
                threat.data_flow_ids = (
                    [edge["id"]] if edge.get("id") else []
                )
                self._model.threats.append(threat)
                self._existing_stride_threats[stride_cat] = threat

    def _generate_attack_surface_threats(
        self, attack_surface: dict[str, Any]
    ) -> None:
        """Generate threats from attack surface analysis results."""
        # From attack vectors
        for av in attack_surface.get("attack_vectors", []):
            vector_type = av.get("vector_type", "")
            stride_cat = ATTACK_VECTOR_TO_STRIDE.get(vector_type)
            if stride_cat is None or stride_cat in self._existing_stride_threats:
                continue

            compliance = self._get_compliance_ids(stride_cat)
            threat = self._create_threat(
                stride_category=stride_cat,
                title=av.get("name", stride_cat.value),
                description=av.get("description", ""),
                severity=av.get("severity", "medium"),
                likelihood=DEFAULT_THREAT_LIKELIHOOD.get(stride_cat, 0.5),
                impact=DEFAULT_THREAT_IMPACT.get(stride_cat, 0.5),
                phase=ThreatModelPhase.DISCOVERY,
                affected_components=av.get("target_components", []),
                compliance=compliance,
            )
            self._model.threats.append(threat)
            self._existing_stride_threats[stride_cat] = threat

    def _finding_to_stride(
        self, finding: dict[str, Any]
    ) -> StrideAICategory | None:
        """Map a finding to a STRIDE-AI category."""
        category = finding.get("category", "")
        return ATTACK_CATEGORY_TO_STRIDE.get(category)

    def _get_compliance_ids(
        self,
        stride_cat: StrideAICategory,
        attack_category: str = "",
    ) -> dict[str, list[str]]:
        """Get compliance framework IDs for a STRIDE-AI category."""
        # Primary source: STRIDE_COMPLIANCE_MAP
        result = STRIDE_COMPLIANCE_MAP.get(stride_cat, {})

        # Supplement from CATEGORY_MAPPINGS if attack_category provided
        if attack_category:
            try:
                from mass.compliance.mappings import CATEGORY_MAPPINGS

                mapping = CATEGORY_MAPPINGS.get(attack_category)
                if mapping:
                    for fw_key, attr_name in [
                        ("owasp_llm", "owasp_llm"),
                        ("mitre_atlas", "mitre_atlas"),
                        ("nist_ai_rmf", "nist_ai_rmf"),
                        ("cwe", "cwe"),
                    ]:
                        extra = getattr(mapping, attr_name, [])
                        if extra:
                            existing = list(result.get(fw_key, []))
                            for item in extra:
                                if item not in existing:
                                    existing.append(item)
                            result = {**result, fw_key: existing}
            except (ImportError, AttributeError):
                pass

        return dict(result)

    def _update_classification_from_finding(
        self, finding: dict[str, Any]
    ) -> None:
        """Upgrade data classification based on finding content."""
        text = (
            finding.get("title", "")
            + " "
            + finding.get("description", "")
        ).lower()
        category = finding.get("category", "")

        if category in ("secrets_exposure", "sensitive_info"):
            self._model.data_classification = max_classification(
                self._model.data_classification,
                DataClassification.CONFIDENTIAL,
            )

        if any(ind in text for ind in PII_INDICATORS + HEALTH_INDICATORS):
            self._model.data_classification = DataClassification.RESTRICTED
            self._model.data_classification_signals.append(
                f"Restricted data indicator in: {finding.get('title', '')[:60]}"
            )

    @staticmethod
    def _severity_to_likelihood(severity: str) -> float:
        """Convert finding severity to a base likelihood."""
        return {
            "critical": 0.8,
            "high": 0.7,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1,
        }.get(severity, 0.5)

    def _aggregate_mitigations(self) -> list[dict[str, Any]]:
        """Deduplicate and prioritize mitigations across all threats."""
        seen: set[str] = set()
        mitigations: list[dict[str, Any]] = []
        priority = 0

        # Sort threats by risk_score descending so higher-risk mitigations come first
        sorted_threats = sorted(
            self._model.threats,
            key=lambda t: t.risk_score,
            reverse=True,
        )

        for threat in sorted_threats:
            for mit_text in threat.mitigations:
                # Simple dedup by lowercase text
                key = mit_text.lower().strip()
                if key in seen or not key:
                    continue
                seen.add(key)
                priority += 1
                mitigations.append({
                    "priority": priority,
                    "title": mit_text.split(":")[0].strip()
                    if ":" in mit_text
                    else mit_text[:80],
                    "description": mit_text,
                    "related_threat": threat.id,
                    "stride_category": threat.stride_category.value,
                })

        return mitigations
