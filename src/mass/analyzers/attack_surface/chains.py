"""Attack chain detection.

Identifies multi-step attack chains across deployment components.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mass.core.types import Severity, ComponentType


class ChainStepType(str, Enum):
    """Types of steps in an attack chain."""
    INJECTION = "injection"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_ACCESS = "data_access"
    EXFILTRATION = "exfiltration"
    PERSISTENCE = "persistence"
    EVASION = "evasion"


@dataclass
class ChainStep:
    """A single step in an attack chain."""
    step_number: int
    step_type: ChainStepType
    component: str
    component_type: ComponentType | None
    action: str
    description: str
    prerequisites: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "step_number": self.step_number,
            "step_type": self.step_type.value,
            "component": self.component,
            "component_type": self.component_type.value if self.component_type else None,
            "action": self.action,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "indicators": self.indicators,
            "mitigations": self.mitigations,
        }


@dataclass
class AttackChain:
    """A complete attack chain across components."""
    id: str
    name: str
    description: str
    severity: Severity
    steps: list[ChainStep] = field(default_factory=list)
    entry_point: str = ""
    final_target: str = ""
    likelihood: float = 0.5
    impact: float = 0.5
    mitre_mapping: list[str] = field(default_factory=list)  # MITRE ATLAS IDs
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "steps": [s.to_dict() for s in self.steps],
            "entry_point": self.entry_point,
            "final_target": self.final_target,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "mitre_mapping": self.mitre_mapping,
            "evidence": self.evidence,
        }

    @property
    def risk_score(self) -> float:
        """Calculate risk score."""
        return self.likelihood * self.impact

    @property
    def step_count(self) -> int:
        """Number of steps in chain."""
        return len(self.steps)


# Known attack chain patterns
KNOWN_ATTACK_CHAINS = [
    {
        "id": "rag_poisoning_chain",
        "name": "RAG Poisoning Attack Chain",
        "description": "Attacker poisons RAG documents to manipulate model output",
        "severity": Severity.HIGH,
        "entry_point": "knowledge_base",
        "final_target": "model_output",
        "steps": [
            {
                "step_type": ChainStepType.INJECTION,
                "action": "inject_malicious_document",
                "description": "Inject document containing prompt injection payload into RAG",
            },
            {
                "step_type": ChainStepType.EXPLOITATION,
                "action": "trigger_retrieval",
                "description": "Craft query that retrieves malicious document",
            },
            {
                "step_type": ChainStepType.EXPLOITATION,
                "action": "manipulate_model",
                "description": "Injected content manipulates model behavior",
            },
        ],
        "mitre_mapping": ["AML.T0030", "AML.T0048"],
    },
    {
        "id": "tool_chaining_chain",
        "name": "Tool Chaining Attack",
        "description": "Attacker chains tool calls to escalate privileges",
        "severity": Severity.CRITICAL,
        "entry_point": "user_input",
        "final_target": "system_access",
        "steps": [
            {
                "step_type": ChainStepType.INJECTION,
                "action": "inject_tool_request",
                "description": "Inject request to invoke benign-looking tool",
            },
            {
                "step_type": ChainStepType.LATERAL_MOVEMENT,
                "action": "chain_tool_calls",
                "description": "First tool result triggers second tool",
            },
            {
                "step_type": ChainStepType.PRIVILEGE_ESCALATION,
                "action": "access_sensitive_tool",
                "description": "Chain leads to sensitive tool execution",
            },
        ],
        "mitre_mapping": ["AML.T0042", "AML.T0050"],
    },
    {
        "id": "context_manipulation_chain",
        "name": "Context Manipulation Chain",
        "description": "Attacker manipulates context to bypass restrictions",
        "severity": Severity.HIGH,
        "entry_point": "conversation",
        "final_target": "model_behavior",
        "steps": [
            {
                "step_type": ChainStepType.INJECTION,
                "action": "inject_context_override",
                "description": "Inject instructions that override system context",
            },
            {
                "step_type": ChainStepType.EVASION,
                "action": "bypass_safety",
                "description": "Manipulated context bypasses safety checks",
            },
            {
                "step_type": ChainStepType.EXPLOITATION,
                "action": "execute_harmful_action",
                "description": "Model executes previously restricted action",
            },
        ],
        "mitre_mapping": ["AML.T0051"],
    },
    {
        "id": "data_exfiltration_chain",
        "name": "Data Exfiltration Chain",
        "description": "Attacker exfiltrates sensitive data through model",
        "severity": Severity.CRITICAL,
        "entry_point": "user_query",
        "final_target": "sensitive_data",
        "steps": [
            {
                "step_type": ChainStepType.INJECTION,
                "action": "craft_extraction_prompt",
                "description": "Craft prompt to extract sensitive information",
            },
            {
                "step_type": ChainStepType.DATA_ACCESS,
                "action": "access_memory_context",
                "description": "Model accesses conversation memory or context",
            },
            {
                "step_type": ChainStepType.EXFILTRATION,
                "action": "extract_data",
                "description": "Sensitive data included in model response",
            },
        ],
        "mitre_mapping": ["AML.T0024", "AML.T0025"],
    },
    {
        "id": "multi_agent_compromise_chain",
        "name": "Multi-Agent Compromise Chain",
        "description": "Attacker compromises one agent to affect others",
        "severity": Severity.HIGH,
        "entry_point": "agent_input",
        "final_target": "agent_network",
        "steps": [
            {
                "step_type": ChainStepType.INJECTION,
                "action": "compromise_agent",
                "description": "Inject malicious content into one agent",
            },
            {
                "step_type": ChainStepType.LATERAL_MOVEMENT,
                "action": "propagate_to_peers",
                "description": "Compromised agent passes payload to other agents",
            },
            {
                "step_type": ChainStepType.PERSISTENCE,
                "action": "establish_foothold",
                "description": "Malicious behavior persists across agent interactions",
            },
        ],
        "mitre_mapping": ["AML.T0040", "AML.T0043"],
    },
    {
        "id": "mcp_privilege_escalation_chain",
        "name": "MCP Privilege Escalation Chain",
        "description": "Attacker uses MCP tools to escalate privileges",
        "severity": Severity.CRITICAL,
        "entry_point": "tool_description",
        "final_target": "system_resources",
        "steps": [
            {
                "step_type": ChainStepType.INJECTION,
                "action": "inject_tool_description",
                "description": "Malicious tool description manipulates tool selection",
            },
            {
                "step_type": ChainStepType.PRIVILEGE_ESCALATION,
                "action": "invoke_privileged_tool",
                "description": "Model invokes tool with elevated permissions",
            },
            {
                "step_type": ChainStepType.EXPLOITATION,
                "action": "access_resources",
                "description": "Tool provides access to restricted resources",
            },
        ],
        "mitre_mapping": ["AML.T0042", "AML.T0050"],
    },
]


class AttackChainDetector:
    """Detects potential attack chains in deployments.

    Analyzes component topology and interactions to identify
    multi-step attack patterns.
    """

    def __init__(self):
        """Initialize chain detector."""
        self._known_chains = KNOWN_ATTACK_CHAINS

    def detect_chains(
        self,
        components: dict[str, ComponentType],
        interactions: list[tuple[str, str, str]],
    ) -> list[AttackChain]:
        """Detect attack chains in deployment.

        Args:
            components: Dict mapping component names to types.
            interactions: List of (source, target, interaction_type).

        Returns:
            List of detected attack chains.
        """
        chains: list[AttackChain] = []

        # Check for known chain patterns
        for chain_template in self._known_chains:
            if self._chain_applicable(chain_template, components, interactions):
                chain = self._instantiate_chain(chain_template, components)
                chains.append(chain)

        # Look for custom chains based on topology
        custom_chains = self._detect_custom_chains(components, interactions)
        chains.extend(custom_chains)

        return chains

    def _chain_applicable(
        self,
        template: dict[str, Any],
        components: dict[str, ComponentType],
        interactions: list[tuple[str, str, str]],
    ) -> bool:
        """Check if a chain template is applicable.

        Args:
            template: Chain template.
            components: Dict mapping component names to types.
            interactions: Component interactions.

        Returns:
            True if chain is applicable.
        """
        chain_id = template["id"]
        component_types = set(components.values())

        # Check based on chain type
        if chain_id == "rag_poisoning_chain":
            return ComponentType.KNOWLEDGE in component_types

        elif chain_id == "tool_chaining_chain":
            return ComponentType.MCP_SERVER in component_types

        elif chain_id == "context_manipulation_chain":
            return ComponentType.CONTEXT in component_types

        elif chain_id == "data_exfiltration_chain":
            return ComponentType.MODEL in component_types

        elif chain_id == "multi_agent_compromise_chain":
            # Need multiple agents/workflows
            return ComponentType.WORKFLOW in component_types

        elif chain_id == "mcp_privilege_escalation_chain":
            return ComponentType.MCP_SERVER in component_types

        return False

    def _instantiate_chain(
        self,
        template: dict[str, Any],
        components: dict[str, ComponentType],
    ) -> AttackChain:
        """Create AttackChain from template.

        Args:
            template: Chain template.
            components: Dict mapping component names to types.

        Returns:
            Instantiated AttackChain.
        """
        steps: list[ChainStep] = []

        for i, step_template in enumerate(template["steps"]):
            # Find component for this step
            component = self._find_step_component(
                step_template["step_type"],
                components,
            )

            step = ChainStep(
                step_number=i + 1,
                step_type=ChainStepType(step_template["step_type"]),
                component=component,
                component_type=components.get(component),
                action=step_template["action"],
                description=step_template["description"],
                mitigations=self._get_step_mitigations(step_template["step_type"]),
            )
            steps.append(step)

        return AttackChain(
            id=template["id"],
            name=template["name"],
            description=template["description"],
            severity=template["severity"],
            steps=steps,
            entry_point=template["entry_point"],
            final_target=template["final_target"],
            likelihood=self._estimate_chain_likelihood(steps),
            impact=self._estimate_chain_impact(template["severity"]),
            mitre_mapping=template.get("mitre_mapping", []),
        )

    def _find_step_component(
        self,
        step_type: str | ChainStepType,
        components: dict[str, ComponentType],
    ) -> str:
        """Find a component for a chain step.

        Args:
            step_type: Type of step.
            components: Available components.

        Returns:
            Component name.
        """
        if isinstance(step_type, str):
            step_type = ChainStepType(step_type)

        # Map step types to component types
        step_to_component = {
            ChainStepType.INJECTION: [
                ComponentType.KNOWLEDGE,
                ComponentType.CONTEXT,
                ComponentType.MCP_SERVER,
            ],
            ChainStepType.EXPLOITATION: [
                ComponentType.MODEL,
                ComponentType.CODE,
            ],
            ChainStepType.PRIVILEGE_ESCALATION: [
                ComponentType.MCP_SERVER,
                ComponentType.CODE,
            ],
            ChainStepType.LATERAL_MOVEMENT: [
                ComponentType.WORKFLOW,
                ComponentType.MCP_SERVER,
            ],
            ChainStepType.DATA_ACCESS: [
                ComponentType.KNOWLEDGE,
                ComponentType.MODEL,
            ],
            ChainStepType.EXFILTRATION: [
                ComponentType.MODEL,
                ComponentType.CODE,
            ],
        }

        preferred_types = step_to_component.get(step_type, [])

        for name, ctype in components.items():
            if ctype in preferred_types:
                return name

        # Return first component if no match
        return next(iter(components.keys()), "unknown")

    def _get_step_mitigations(self, step_type: str | ChainStepType) -> list[str]:
        """Get mitigations for a step type.

        Args:
            step_type: Type of step.

        Returns:
            List of mitigations.
        """
        if isinstance(step_type, str):
            step_type = ChainStepType(step_type)

        mitigations = {
            ChainStepType.INJECTION: [
                "Validate and sanitize all inputs",
                "Implement content filtering",
            ],
            ChainStepType.EXPLOITATION: [
                "Add output validation",
                "Implement rate limiting",
            ],
            ChainStepType.PRIVILEGE_ESCALATION: [
                "Apply principle of least privilege",
                "Add approval workflows for sensitive operations",
            ],
            ChainStepType.LATERAL_MOVEMENT: [
                "Isolate components with network segmentation",
                "Validate inter-component messages",
            ],
            ChainStepType.DATA_ACCESS: [
                "Implement access controls",
                "Encrypt sensitive data",
            ],
            ChainStepType.EXFILTRATION: [
                "Monitor outbound data",
                "Implement data loss prevention",
            ],
            ChainStepType.PERSISTENCE: [
                "Clear conversation state regularly",
                "Audit and rotate credentials",
            ],
            ChainStepType.EVASION: [
                "Layer multiple detection mechanisms",
                "Log and monitor all operations",
            ],
        }

        return mitigations.get(step_type, ["Review security controls"])

    def _estimate_chain_likelihood(self, steps: list[ChainStep]) -> float:
        """Estimate likelihood of chain execution.

        Args:
            steps: Chain steps.

        Returns:
            Likelihood score.
        """
        # Each step reduces likelihood
        base = 0.8
        reduction_per_step = 0.1

        return max(base - (len(steps) - 1) * reduction_per_step, 0.2)

    def _estimate_chain_impact(self, severity: Severity) -> float:
        """Estimate impact from severity.

        Args:
            severity: Chain severity.

        Returns:
            Impact score.
        """
        impact_map = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }

        return impact_map.get(severity, 0.5)

    def _detect_custom_chains(
        self,
        components: dict[str, ComponentType],
        interactions: list[tuple[str, str, str]],
    ) -> list[AttackChain]:
        """Detect custom attack chains from topology.

        Args:
            components: Dict mapping component names to types.
            interactions: Component interactions.

        Returns:
            List of custom attack chains.
        """
        chains: list[AttackChain] = []

        # Build adjacency map
        adj_map: dict[str, list[str]] = {}
        for source, target, _ in interactions:
            if source not in adj_map:
                adj_map[source] = []
            adj_map[source].append(target)

        # Look for paths from external to internal components
        external = [
            name for name, ctype in components.items()
            if ctype in (ComponentType.KNOWLEDGE, ComponentType.MCP_SERVER)
        ]

        internal = [
            name for name, ctype in components.items()
            if ctype == ComponentType.MODEL
        ]

        chain_id = 100
        for ext in external:
            for int_comp in internal:
                paths = self._find_paths(ext, int_comp, adj_map)
                for path in paths:
                    if len(path) > 2:  # Multi-step chains
                        chain_id += 1
                        chain = self._create_custom_chain(
                            f"custom_chain_{chain_id}",
                            path,
                            components,
                        )
                        chains.append(chain)

        return chains

    def _find_paths(
        self,
        start: str,
        end: str,
        adj_map: dict[str, list[str]],
        max_depth: int = 5,
    ) -> list[list[str]]:
        """Find paths between two nodes.

        Args:
            start: Start node.
            end: End node.
            adj_map: Adjacency map.
            max_depth: Maximum path length.

        Returns:
            List of paths.
        """
        paths: list[list[str]] = []

        def dfs(current: str, path: list[str], visited: set[str]) -> None:
            if len(path) > max_depth:
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

    def _create_custom_chain(
        self,
        chain_id: str,
        path: list[str],
        components: dict[str, ComponentType],
    ) -> AttackChain:
        """Create a custom attack chain from a path.

        Args:
            chain_id: Unique chain ID.
            path: List of component names.
            components: Dict mapping component names to types.

        Returns:
            Custom AttackChain.
        """
        steps: list[ChainStep] = []

        for i, comp in enumerate(path):
            step_type = self._infer_step_type(i, len(path))

            step = ChainStep(
                step_number=i + 1,
                step_type=step_type,
                component=comp,
                component_type=components.get(comp),
                action=f"traverse_{comp}",
                description=f"Attack reaches {comp}",
            )
            steps.append(step)

        return AttackChain(
            id=chain_id,
            name=f"Custom Chain: {path[0]} to {path[-1]}",
            description=f"Potential attack path: {' -> '.join(path)}",
            severity=Severity.MEDIUM,
            steps=steps,
            entry_point=path[0],
            final_target=path[-1],
            likelihood=self._estimate_chain_likelihood(steps),
            impact=0.6,
        )

    def _infer_step_type(self, position: int, total: int) -> ChainStepType:
        """Infer step type from position in chain.

        Args:
            position: Position in chain (0-indexed).
            total: Total steps in chain.

        Returns:
            Inferred step type.
        """
        if position == 0:
            return ChainStepType.INJECTION
        elif position == total - 1:
            return ChainStepType.EXPLOITATION
        else:
            return ChainStepType.LATERAL_MOVEMENT
