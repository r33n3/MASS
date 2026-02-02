"""Attack surface analyzer.

Identifies and maps the attack surface of AI deployments.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator

from mass.core.types import Severity, ComponentType

logger = logging.getLogger(__name__)


class AttackVectorType(str, Enum):
    """Types of attack vectors."""
    USER_INPUT = "user_input"
    FILE_UPLOAD = "file_upload"
    API_ENDPOINT = "api_endpoint"
    DATABASE_QUERY = "database_query"
    EXTERNAL_SERVICE = "external_service"
    RAG_RETRIEVAL = "rag_retrieval"
    TOOL_INVOCATION = "tool_invocation"
    AGENT_COMMUNICATION = "agent_communication"
    CONTEXT_INJECTION = "context_injection"
    MODEL_INFERENCE = "model_inference"
    MEMORY_ACCESS = "memory_access"
    WEBHOOK = "webhook"


class ThreatCategory(str, Enum):
    """Categories of threats."""
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DENIAL_OF_SERVICE = "denial_of_service"
    DATA_POISONING = "data_poisoning"
    MODEL_MANIPULATION = "model_manipulation"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    INFORMATION_DISCLOSURE = "information_disclosure"
    SUPPLY_CHAIN = "supply_chain"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class AttackVector:
    """A potential attack vector in the system."""
    id: str
    name: str
    vector_type: AttackVectorType
    severity: Severity
    description: str
    entry_point: str
    target_components: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "vector_type": self.vector_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "entry_point": self.entry_point,
            "target_components": self.target_components,
            "prerequisites": self.prerequisites,
            "mitigations": self.mitigations,
            "metadata": self.metadata,
        }


@dataclass
class ComponentInteraction:
    """An interaction between deployment components."""
    source: str
    source_type: ComponentType
    target: str
    target_type: ComponentType
    interaction_type: str  # data_flow, tool_call, api_call, etc.
    data_types: list[str] = field(default_factory=list)
    trust_boundary: bool = False
    risk_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source": self.source,
            "source_type": self.source_type.value,
            "target": self.target,
            "target_type": self.target_type.value,
            "interaction_type": self.interaction_type,
            "data_types": self.data_types,
            "trust_boundary": self.trust_boundary,
            "risk_factors": self.risk_factors,
        }


@dataclass
class VulnerabilityPath:
    """A path through the system that could be exploited."""
    id: str
    name: str
    severity: Severity
    threat_category: ThreatCategory
    steps: list[str]  # Component IDs in order
    description: str
    likelihood: float = 0.5  # 0.0 to 1.0
    impact: float = 0.5  # 0.0 to 1.0
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "threat_category": self.threat_category.value,
            "steps": self.steps,
            "description": self.description,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    @property
    def risk_score(self) -> float:
        """Calculate risk score from likelihood and impact."""
        return self.likelihood * self.impact


@dataclass
class ThreatModel:
    """A threat model for the deployment."""
    name: str
    description: str
    assets: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    attack_vectors: list[AttackVector] = field(default_factory=list)
    vulnerability_paths: list[VulnerabilityPath] = field(default_factory=list)
    mitigations: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "assets": self.assets,
            "threat_actors": self.threat_actors,
            "attack_vectors": [v.to_dict() for v in self.attack_vectors],
            "vulnerability_paths": [p.to_dict() for p in self.vulnerability_paths],
            "mitigations": self.mitigations,
        }


@dataclass
class AttackSurfaceResult:
    """Result of attack surface analysis."""
    components: list[str] = field(default_factory=list)
    interactions: list[ComponentInteraction] = field(default_factory=list)
    attack_vectors: list[AttackVector] = field(default_factory=list)
    vulnerability_paths: list[VulnerabilityPath] = field(default_factory=list)
    threat_model: ThreatModel | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def total_attack_vectors(self) -> int:
        """Total number of attack vectors."""
        return len(self.attack_vectors)

    @property
    def critical_paths(self) -> list[VulnerabilityPath]:
        """Get critical vulnerability paths."""
        return [p for p in self.vulnerability_paths if p.severity == Severity.CRITICAL]

    @property
    def high_risk_paths(self) -> list[VulnerabilityPath]:
        """Get high and critical vulnerability paths."""
        return [
            p for p in self.vulnerability_paths
            if p.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "components": self.components,
            "interactions": [i.to_dict() for i in self.interactions],
            "attack_vectors": [v.to_dict() for v in self.attack_vectors],
            "vulnerability_paths": [p.to_dict() for p in self.vulnerability_paths],
            "threat_model": self.threat_model.to_dict() if self.threat_model else None,
            "errors": self.errors,
        }


# Known attack vector patterns
ATTACK_VECTOR_PATTERNS = [
    {
        "name": "User Input Injection",
        "vector_type": AttackVectorType.USER_INPUT,
        "entry_point": "user_message",
        "description": "Malicious input from user can inject prompts or commands",
        "severity": Severity.HIGH,
        "targets": [ComponentType.MODEL, ComponentType.CONTEXT],
    },
    {
        "name": "RAG Document Poisoning",
        "vector_type": AttackVectorType.RAG_RETRIEVAL,
        "entry_point": "knowledge_base",
        "description": "Poisoned documents in RAG can inject malicious content",
        "severity": Severity.HIGH,
        "targets": [ComponentType.KNOWLEDGE, ComponentType.MODEL],
    },
    {
        "name": "Tool Result Injection",
        "vector_type": AttackVectorType.TOOL_INVOCATION,
        "entry_point": "tool_response",
        "description": "Malicious tool outputs can manipulate model behavior",
        "severity": Severity.MEDIUM,
        "targets": [ComponentType.MCP_SERVER, ComponentType.MODEL],
    },
    {
        "name": "Inter-Agent Message Injection",
        "vector_type": AttackVectorType.AGENT_COMMUNICATION,
        "entry_point": "agent_message",
        "description": "Messages between agents can carry injection payloads",
        "severity": Severity.MEDIUM,
        "targets": [ComponentType.WORKFLOW],
    },
    {
        "name": "Context File Manipulation",
        "vector_type": AttackVectorType.CONTEXT_INJECTION,
        "entry_point": "context_file",
        "description": "Modified context files can change model behavior",
        "severity": Severity.CRITICAL,
        "targets": [ComponentType.CONTEXT],
    },
    {
        "name": "External API Response Injection",
        "vector_type": AttackVectorType.EXTERNAL_SERVICE,
        "entry_point": "api_response",
        "description": "External service responses may contain malicious content",
        "severity": Severity.MEDIUM,
        "targets": [ComponentType.CODE],
    },
    {
        "name": "File Upload Attack",
        "vector_type": AttackVectorType.FILE_UPLOAD,
        "entry_point": "file_upload",
        "description": "Uploaded files may contain malicious content or code",
        "severity": Severity.HIGH,
        "targets": [ComponentType.CODE, ComponentType.KNOWLEDGE],
    },
    {
        "name": "Memory Manipulation",
        "vector_type": AttackVectorType.MEMORY_ACCESS,
        "entry_point": "conversation_memory",
        "description": "Conversation history can be poisoned to influence behavior",
        "severity": Severity.MEDIUM,
        "targets": [ComponentType.MODEL],
    },
]


class AttackSurfaceAnalyzer:
    """Analyzes the attack surface of AI deployments.

    Identifies:
    - Attack vectors (entry points for attacks)
    - Component interactions (data flows)
    - Vulnerability paths (chains of exploitation)
    - Threat models (comprehensive risk assessment)
    """

    def __init__(self):
        """Initialize attack surface analyzer."""
        self._vector_patterns = ATTACK_VECTOR_PATTERNS

    def analyze(
        self,
        components: dict[str, ComponentType],
        interactions: list[tuple[str, str, str]] | None = None,
    ) -> AttackSurfaceResult:
        """Analyze attack surface of a deployment.

        Args:
            components: Dict mapping component names to types.
            interactions: Optional list of (source, target, interaction_type).

        Returns:
            Attack surface analysis result.
        """
        result = AttackSurfaceResult(
            components=list(components.keys()),
        )

        # Build component interactions
        if interactions:
            for source, target, int_type in interactions:
                source_type = components.get(source, ComponentType.CODE)
                target_type = components.get(target, ComponentType.CODE)

                interaction = ComponentInteraction(
                    source=source,
                    source_type=source_type,
                    target=target,
                    target_type=target_type,
                    interaction_type=int_type,
                    trust_boundary=self._crosses_trust_boundary(source_type, target_type),
                )
                result.interactions.append(interaction)

        # Identify attack vectors
        attack_vectors = list(self._identify_attack_vectors(components))
        result.attack_vectors.extend(attack_vectors)

        # Find vulnerability paths
        vuln_paths = list(self._find_vulnerability_paths(components, result.interactions))
        result.vulnerability_paths.extend(vuln_paths)

        # Build threat model
        result.threat_model = self._build_threat_model(result)

        return result

    def _crosses_trust_boundary(
        self,
        source_type: ComponentType,
        target_type: ComponentType,
    ) -> bool:
        """Check if interaction crosses a trust boundary.

        Args:
            source_type: Source component type.
            target_type: Target component type.

        Returns:
            True if crosses trust boundary.
        """
        # Trust boundaries between external/internal components
        external_types = {
            ComponentType.MCP_SERVER,
            ComponentType.KNOWLEDGE,
        }

        internal_types = {
            ComponentType.MODEL,
            ComponentType.CONTEXT,
            ComponentType.CODE,
        }

        return (
            (source_type in external_types and target_type in internal_types) or
            (source_type in internal_types and target_type in external_types)
        )

    def _identify_attack_vectors(
        self,
        components: dict[str, ComponentType],
    ) -> Iterator[AttackVector]:
        """Identify attack vectors based on components.

        Args:
            components: Dict mapping component names to types.

        Yields:
            Attack vectors.
        """
        component_types = set(components.values())

        for pattern in self._vector_patterns:
            # Check if any target components exist
            targets_present = any(
                t in component_types for t in pattern["targets"]
            )

            if targets_present:
                # Find matching components
                target_names = [
                    name for name, ctype in components.items()
                    if ctype in pattern["targets"]
                ]

                yield AttackVector(
                    id=f"av_{pattern['vector_type'].value}",
                    name=pattern["name"],
                    vector_type=pattern["vector_type"],
                    severity=pattern["severity"],
                    description=pattern["description"],
                    entry_point=pattern["entry_point"],
                    target_components=target_names,
                )

    def _find_vulnerability_paths(
        self,
        components: dict[str, ComponentType],
        interactions: list[ComponentInteraction],
    ) -> Iterator[VulnerabilityPath]:
        """Find vulnerability paths through components.

        Args:
            components: Dict mapping component names to types.
            interactions: Component interactions.

        Yields:
            Vulnerability paths.
        """
        # Build adjacency map
        adj_map: dict[str, list[str]] = {}
        for interaction in interactions:
            if interaction.source not in adj_map:
                adj_map[interaction.source] = []
            adj_map[interaction.source].append(interaction.target)

        # Find paths from entry points to sensitive components
        entry_points = self._find_entry_points(components)
        sensitive = self._find_sensitive_components(components)

        path_id = 0
        for entry in entry_points:
            for target in sensitive:
                paths = self._find_all_paths(entry, target, adj_map)
                for path in paths:
                    path_id += 1
                    yield VulnerabilityPath(
                        id=f"vp_{path_id}",
                        name=f"Path from {entry} to {target}",
                        severity=self._assess_path_severity(path, components),
                        threat_category=self._infer_threat_category(path, components),
                        steps=path,
                        description=f"Attack path: {' -> '.join(path)}",
                        likelihood=self._estimate_likelihood(path, interactions),
                        impact=self._estimate_impact(target, components),
                        remediation=self._suggest_remediation(path, components),
                    )

    def _find_entry_points(
        self,
        components: dict[str, ComponentType],
    ) -> list[str]:
        """Find entry point components.

        Args:
            components: Dict mapping component names to types.

        Returns:
            List of entry point component names.
        """
        entry_types = {
            ComponentType.MCP_SERVER,
            ComponentType.KNOWLEDGE,
            ComponentType.CONFIG,
        }

        entry_names = ["user_input", "api_input", "file_upload"]

        entries = [
            name for name, ctype in components.items()
            if ctype in entry_types or any(n in name.lower() for n in entry_names)
        ]

        # Always include user input as potential entry
        if "user_input" not in entries and "user" not in str(entries).lower():
            entries.append("user_input")

        return entries

    def _find_sensitive_components(
        self,
        components: dict[str, ComponentType],
    ) -> list[str]:
        """Find sensitive target components.

        Args:
            components: Dict mapping component names to types.

        Returns:
            List of sensitive component names.
        """
        sensitive_types = {
            ComponentType.MODEL,
            ComponentType.CONTEXT,
            ComponentType.CODE,
        }

        sensitive_keywords = ["model", "llm", "context", "system", "admin", "secret"]

        return [
            name for name, ctype in components.items()
            if ctype in sensitive_types or any(k in name.lower() for k in sensitive_keywords)
        ]

    def _find_all_paths(
        self,
        start: str,
        end: str,
        adj_map: dict[str, list[str]],
        max_paths: int = 5,
    ) -> list[list[str]]:
        """Find all paths between two nodes.

        Args:
            start: Start node.
            end: End node.
            adj_map: Adjacency map.
            max_paths: Maximum paths to return.

        Returns:
            List of paths.
        """
        paths: list[list[str]] = []

        def dfs(current: str, path: list[str], visited: set[str]) -> None:
            if len(paths) >= max_paths:
                return

            if current == end:
                paths.append(path.copy())
                return

            for neighbor in adj_map.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs(neighbor, path, visited)
                    path.pop()
                    visited.remove(neighbor)

        dfs(start, [start], {start})
        return paths

    def _assess_path_severity(
        self,
        path: list[str],
        components: dict[str, ComponentType],
    ) -> Severity:
        """Assess severity of a vulnerability path.

        Args:
            path: List of component names in path.
            components: Dict mapping component names to types.

        Returns:
            Severity level.
        """
        # Longer paths through sensitive components are higher severity
        path_length = len(path)
        sensitive_count = sum(
            1 for p in path
            if components.get(p) in (ComponentType.MODEL, ComponentType.CONTEXT)
        )

        if sensitive_count >= 2 and path_length <= 3:
            return Severity.CRITICAL
        elif sensitive_count >= 1:
            return Severity.HIGH
        elif path_length <= 2:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _infer_threat_category(
        self,
        path: list[str],
        components: dict[str, ComponentType],
    ) -> ThreatCategory:
        """Infer threat category from path.

        Args:
            path: List of component names in path.
            components: Dict mapping component names to types.

        Returns:
            Threat category.
        """
        path_types = [components.get(p) for p in path]

        if ComponentType.MODEL in path_types:
            if ComponentType.KNOWLEDGE in path_types:
                return ThreatCategory.DATA_POISONING
            return ThreatCategory.PROMPT_INJECTION

        if ComponentType.MCP_SERVER in path_types:
            return ThreatCategory.PRIVILEGE_ESCALATION

        if ComponentType.CONTEXT in path_types:
            return ThreatCategory.INFORMATION_DISCLOSURE

        return ThreatCategory.LATERAL_MOVEMENT

    def _estimate_likelihood(
        self,
        path: list[str],
        interactions: list[ComponentInteraction],
    ) -> float:
        """Estimate likelihood of exploiting a path.

        Args:
            path: List of component names in path.
            interactions: Component interactions.

        Returns:
            Likelihood score (0.0 to 1.0).
        """
        # Shorter paths are more likely to be exploited
        base_likelihood = 1.0 / len(path) if path else 0.0

        # Paths crossing trust boundaries are slightly less likely
        trust_crossings = sum(
            1 for i in interactions
            if i.trust_boundary and i.source in path and i.target in path
        )

        return min(base_likelihood * (1.0 - 0.1 * trust_crossings), 1.0)

    def _estimate_impact(
        self,
        target: str,
        components: dict[str, ComponentType],
    ) -> float:
        """Estimate impact of compromising a target.

        Args:
            target: Target component name.
            components: Dict mapping component names to types.

        Returns:
            Impact score (0.0 to 1.0).
        """
        target_type = components.get(target)

        impact_scores = {
            ComponentType.MODEL: 0.9,
            ComponentType.CONTEXT: 0.8,
            ComponentType.CODE: 0.7,
            ComponentType.MCP_SERVER: 0.6,
            ComponentType.KNOWLEDGE: 0.5,
            ComponentType.CONFIG: 0.6,
        }

        return impact_scores.get(target_type, 0.5)

    def _suggest_remediation(
        self,
        path: list[str],
        components: dict[str, ComponentType],
    ) -> str:
        """Suggest remediation for a vulnerability path.

        Args:
            path: List of component names in path.
            components: Dict mapping component names to types.

        Returns:
            Remediation suggestion.
        """
        suggestions = []

        if len(path) > 2:
            suggestions.append("Add input validation between components")

        path_types = [components.get(p) for p in path]

        if ComponentType.MODEL in path_types:
            suggestions.append("Implement prompt filtering and output validation")

        if ComponentType.MCP_SERVER in path_types:
            suggestions.append("Restrict tool permissions and add approval workflows")

        if ComponentType.KNOWLEDGE in path_types:
            suggestions.append("Validate and sanitize RAG document content")

        return "; ".join(suggestions) if suggestions else "Review component security"

    def _build_threat_model(
        self,
        result: AttackSurfaceResult,
    ) -> ThreatModel:
        """Build comprehensive threat model.

        Args:
            result: Analysis result to build from.

        Returns:
            ThreatModel.
        """
        # Identify assets
        assets = result.components.copy()

        # Define common threat actors
        threat_actors = [
            "Malicious User",
            "Compromised External Service",
            "Supply Chain Attacker",
            "Insider Threat",
        ]

        # Collect mitigations
        mitigations: dict[str, list[str]] = {}
        for path in result.vulnerability_paths:
            if path.remediation:
                category = path.threat_category.value
                if category not in mitigations:
                    mitigations[category] = []
                if path.remediation not in mitigations[category]:
                    mitigations[category].append(path.remediation)

        return ThreatModel(
            name="AI Deployment Threat Model",
            description="Comprehensive threat model for AI deployment security",
            assets=assets,
            threat_actors=threat_actors,
            attack_vectors=result.attack_vectors,
            vulnerability_paths=result.vulnerability_paths,
            mitigations=mitigations,
        )
