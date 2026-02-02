"""Workflow security analyzer.

Main analyzer for agentic workflow security analysis.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from mass.core.types import Severity

logger = logging.getLogger(__name__)


class WorkflowRiskCategory(str, Enum):
    """Categories of workflow security risks."""
    UNRESTRICTED_AGENT = "unrestricted_agent"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    UNVALIDATED_TOOL_USE = "unvalidated_tool_use"
    PROMPT_INJECTION_VECTOR = "prompt_injection_vector"
    DATA_FLOW_LEAK = "data_flow_leak"
    RECURSIVE_LOOP = "recursive_loop"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNSAFE_DELEGATION = "unsafe_delegation"
    MISSING_HUMAN_OVERSIGHT = "missing_human_oversight"
    MEMORY_POISONING = "memory_poisoning"
    TOOL_CHAINING = "tool_chaining"
    RAG_POISONING = "rag_poisoning"
    OUTPUT_MANIPULATION = "output_manipulation"


class AgentRole(str, Enum):
    """Common agent roles in workflows."""
    ORCHESTRATOR = "orchestrator"
    PLANNER = "planner"
    EXECUTOR = "executor"
    REVIEWER = "reviewer"
    TOOL_USER = "tool_user"
    RESEARCHER = "researcher"
    CODER = "coder"
    WRITER = "writer"
    CUSTOM = "custom"


class WorkflowFramework(str, Enum):
    """Supported workflow frameworks."""
    LANGCHAIN = "langchain"
    LANGGRAPH = "langgraph"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    OPENAI_AGENTS = "openai_agents"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


@dataclass
class WorkflowNode:
    """A node in the workflow graph."""
    id: str
    name: str
    node_type: str  # agent, tool, router, memory, etc.
    role: AgentRole = AgentRole.CUSTOM
    description: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    tools: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "node_type": self.node_type,
            "role": self.role.value,
            "description": self.description,
            "config": self.config,
            "tools": self.tools,
            "metadata": self.metadata,
        }


@dataclass
class WorkflowEdge:
    """An edge in the workflow graph."""
    source: str
    target: str
    edge_type: str = "flow"  # flow, conditional, tool_call, etc.
    condition: str | None = None
    data_flow: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type,
            "condition": self.condition,
            "data_flow": self.data_flow,
            "metadata": self.metadata,
        }


@dataclass
class WorkflowGraph:
    """Graph representation of a workflow."""
    name: str
    framework: WorkflowFramework
    nodes: list[WorkflowNode] = field(default_factory=list)
    edges: list[WorkflowEdge] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_node(self, node_id: str) -> WorkflowNode | None:
        """Get node by ID."""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def get_outgoing_edges(self, node_id: str) -> list[WorkflowEdge]:
        """Get edges from a node."""
        return [e for e in self.edges if e.source == node_id]

    def get_incoming_edges(self, node_id: str) -> list[WorkflowEdge]:
        """Get edges to a node."""
        return [e for e in self.edges if e.target == node_id]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "framework": self.framework.value,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "entry_points": self.entry_points,
            "metadata": self.metadata,
        }


@dataclass
class WorkflowFinding:
    """A security finding in a workflow."""
    category: WorkflowRiskCategory
    severity: Severity
    title: str
    description: str
    node_id: str | None = None
    edge_id: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None
    attack_path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "node_id": self.node_id,
            "edge_id": self.edge_id,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "attack_path": self.attack_path,
        }


@dataclass
class WorkflowAnalysisResult:
    """Result of workflow analysis."""
    graph: WorkflowGraph
    findings: list[WorkflowFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """Check if no security issues were found."""
        return len(self.findings) == 0

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def findings_by_category(
        self,
        category: WorkflowRiskCategory,
    ) -> list[WorkflowFinding]:
        """Get findings filtered by category."""
        return [f for f in self.findings if f.category == category]


# Patterns for detecting workflow issues
AGENT_RISK_PATTERNS = [
    {
        "pattern": r"(any|all|unlimited|unrestricted)\s*(tools?|actions?|permissions?)",
        "category": WorkflowRiskCategory.EXCESSIVE_PERMISSIONS,
        "severity": Severity.HIGH,
        "title": "Excessive agent permissions",
        "description": "Agent has unrestricted access to tools or actions",
    },
    {
        "pattern": r"(auto|automatic)\s*(execute|run|approve)",
        "category": WorkflowRiskCategory.MISSING_HUMAN_OVERSIGHT,
        "severity": Severity.MEDIUM,
        "title": "Missing human oversight",
        "description": "Agent actions are automatically executed without human review",
    },
    {
        "pattern": r"(delegate|hand\s*off|pass)\s*(to\s+)?(any|other|unknown)",
        "category": WorkflowRiskCategory.UNSAFE_DELEGATION,
        "severity": Severity.HIGH,
        "title": "Unsafe task delegation",
        "description": "Agent delegates tasks without proper validation",
    },
    {
        "pattern": r"(no|without|skip)\s*(validation|check|verification)",
        "category": WorkflowRiskCategory.UNVALIDATED_TOOL_USE,
        "severity": Severity.HIGH,
        "title": "Unvalidated tool usage",
        "description": "Tool calls are made without input validation",
    },
    {
        "pattern": r"(loop|cycle|recursive)\s*(until|forever|infinite)",
        "category": WorkflowRiskCategory.RECURSIVE_LOOP,
        "severity": Severity.MEDIUM,
        "title": "Potential infinite loop",
        "description": "Workflow may enter an infinite loop condition",
    },
]


class WorkflowAnalyzer:
    """Analyzes agentic workflows for security vulnerabilities.

    Supports multiple frameworks:
    - LangChain
    - LangGraph
    - CrewAI
    - AutoGen
    - OpenAI Agents SDK

    Checks for:
    - Excessive agent permissions
    - Unsafe tool usage
    - Missing human oversight
    - Data flow leakage
    - Prompt injection vectors
    - Attack chains across agents
    """

    def __init__(self):
        """Initialize workflow analyzer."""
        # Compile risk patterns
        self._risk_patterns = [
            {
                **risk,
                "compiled": re.compile(risk["pattern"], re.IGNORECASE),
            }
            for risk in AGENT_RISK_PATTERNS
        ]

        # Framework-specific analyzers (lazy loaded)
        self._framework_analyzers: dict[WorkflowFramework, Any] = {}

    def analyze_file(self, file_path: Path | str) -> WorkflowAnalysisResult:
        """Analyze a workflow file.

        Args:
            file_path: Path to workflow file (Python, YAML, etc.).

        Returns:
            Analysis result with graph and findings.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            graph = WorkflowGraph(
                name="unknown",
                framework=WorkflowFramework.UNKNOWN,
            )
            return WorkflowAnalysisResult(
                graph=graph,
                errors=[f"File not found: {file_path}"],
            )

        # Read file content
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            graph = WorkflowGraph(
                name=file_path.name,
                framework=WorkflowFramework.UNKNOWN,
            )
            return WorkflowAnalysisResult(
                graph=graph,
                errors=[f"Error reading file: {e}"],
            )

        # Detect framework
        framework = self.detect_framework(content)

        # Build graph from content
        graph = self._build_graph_from_content(file_path.stem, content, framework)

        # Analyze the graph
        return self.analyze_graph(graph)

    def analyze_graph(self, graph: WorkflowGraph) -> WorkflowAnalysisResult:
        """Analyze a workflow graph.

        Args:
            graph: Workflow graph to analyze.

        Returns:
            Analysis result with findings.
        """
        result = WorkflowAnalysisResult(graph=graph)

        # Analyze each node
        for node in graph.nodes:
            node_findings = list(self._analyze_node(node, graph))
            result.findings.extend(node_findings)

        # Analyze edges for data flow issues
        for edge in graph.edges:
            edge_findings = list(self._analyze_edge(edge, graph))
            result.findings.extend(edge_findings)

        # Check for structural issues
        structural_findings = list(self._check_structural_issues(graph))
        result.findings.extend(structural_findings)

        # Check for attack paths
        attack_findings = list(self._identify_attack_paths(graph))
        result.findings.extend(attack_findings)

        return result

    def detect_framework(self, content: str) -> WorkflowFramework:
        """Detect workflow framework from code content.

        Args:
            content: Source code content.

        Returns:
            Detected framework.
        """
        # LangGraph detection (most specific first)
        if any(pattern in content for pattern in [
            "from langgraph",
            "import langgraph",
            "StateGraph",
            "MessageGraph",
        ]):
            return WorkflowFramework.LANGGRAPH

        # LangChain detection
        if any(pattern in content for pattern in [
            "from langchain",
            "import langchain",
            "LLMChain",
            "AgentExecutor",
            "create_react_agent",
        ]):
            return WorkflowFramework.LANGCHAIN

        # AutoGen detection (before CrewAI - uses specific Agent types)
        if any(pattern in content for pattern in [
            "from autogen",
            "import autogen",
            "AssistantAgent",
            "UserProxyAgent",
            "GroupChat",
        ]):
            return WorkflowFramework.AUTOGEN

        # CrewAI detection (after AutoGen - generic Agent() pattern)
        if any(pattern in content for pattern in [
            "from crewai",
            "import crewai",
            "Crew(",
            "Agent(",
            "Task(",
        ]):
            return WorkflowFramework.CREWAI

        # OpenAI Agents detection (last - also uses generic Agent())
        if any(pattern in content for pattern in [
            "from openai.agents",
            "import openai.agents",
            "Runner(",
            "swarm",
        ]):
            return WorkflowFramework.OPENAI_AGENTS

        return WorkflowFramework.UNKNOWN

    def _build_graph_from_content(
        self,
        name: str,
        content: str,
        framework: WorkflowFramework,
    ) -> WorkflowGraph:
        """Build graph from source content.

        Args:
            name: Graph name.
            content: Source code content.
            framework: Detected framework.

        Returns:
            WorkflowGraph with detected nodes and edges.
        """
        graph = WorkflowGraph(name=name, framework=framework)

        # Extract agents/nodes based on framework
        if framework == WorkflowFramework.CREWAI:
            graph = self._parse_crewai(content, graph)
        elif framework == WorkflowFramework.LANGGRAPH:
            graph = self._parse_langgraph(content, graph)
        elif framework == WorkflowFramework.AUTOGEN:
            graph = self._parse_autogen(content, graph)
        else:
            # Generic extraction
            graph = self._parse_generic(content, graph)

        return graph

    def _parse_crewai(self, content: str, graph: WorkflowGraph) -> WorkflowGraph:
        """Parse CrewAI workflow.

        Args:
            content: Source code.
            graph: Graph to populate.

        Returns:
            Populated graph.
        """
        # Find Agent definitions
        agent_pattern = re.compile(
            r"(\w+)\s*=\s*Agent\s*\(\s*"
            r"(?:role\s*=\s*['\"]([^'\"]+)['\"])?",
            re.MULTILINE | re.IGNORECASE,
        )

        for match in agent_pattern.finditer(content):
            var_name = match.group(1)
            role = match.group(2) or "Agent"

            node = WorkflowNode(
                id=var_name,
                name=role,
                node_type="agent",
                role=self._infer_agent_role(role),
                metadata={"framework": "crewai"},
            )
            graph.nodes.append(node)

        # Find Task definitions and link to agents
        task_pattern = re.compile(
            r"Task\s*\(\s*.*?agent\s*=\s*(\w+)",
            re.MULTILINE | re.DOTALL,
        )

        for match in task_pattern.finditer(content):
            agent_name = match.group(1)
            # Create implicit edges between agents in sequential task order
            # For now, mark as potential edge
            pass

        # Find Crew definition for execution order
        crew_pattern = re.compile(
            r"Crew\s*\(\s*.*?agents\s*=\s*\[(.*?)\]",
            re.MULTILINE | re.DOTALL,
        )

        crew_match = crew_pattern.search(content)
        if crew_match:
            agents_str = crew_match.group(1)
            agent_refs = re.findall(r"(\w+)", agents_str)

            # Create edges between sequential agents
            for i in range(len(agent_refs) - 1):
                edge = WorkflowEdge(
                    source=agent_refs[i],
                    target=agent_refs[i + 1],
                    edge_type="flow",
                )
                graph.edges.append(edge)

            if agent_refs:
                graph.entry_points.append(agent_refs[0])

        return graph

    def _parse_langgraph(self, content: str, graph: WorkflowGraph) -> WorkflowGraph:
        """Parse LangGraph workflow.

        Args:
            content: Source code.
            graph: Graph to populate.

        Returns:
            Populated graph.
        """
        # Find add_node calls
        add_node_pattern = re.compile(
            r"\.add_node\s*\(\s*['\"](\w+)['\"]",
            re.MULTILINE,
        )

        for match in add_node_pattern.finditer(content):
            node_name = match.group(1)
            node = WorkflowNode(
                id=node_name,
                name=node_name,
                node_type="node",
                metadata={"framework": "langgraph"},
            )
            graph.nodes.append(node)

        # Find add_edge calls
        add_edge_pattern = re.compile(
            r"\.add_edge\s*\(\s*['\"](\w+)['\"],\s*['\"](\w+)['\"]",
            re.MULTILINE,
        )

        for match in add_edge_pattern.finditer(content):
            source = match.group(1)
            target = match.group(2)

            # Handle special nodes
            if source.upper() == "START":
                graph.entry_points.append(target)
                continue
            if target.upper() == "END":
                continue

            edge = WorkflowEdge(
                source=source,
                target=target,
                edge_type="flow",
            )
            graph.edges.append(edge)

        # Find conditional edges
        cond_edge_pattern = re.compile(
            r"\.add_conditional_edges\s*\(\s*['\"](\w+)['\"]",
            re.MULTILINE,
        )

        for match in cond_edge_pattern.finditer(content):
            source = match.group(1)
            # Conditional edges go to multiple targets
            # Mark the source as having conditional routing
            source_node = graph.get_node(source)
            if source_node:
                source_node.metadata["has_conditional_routing"] = True

        return graph

    def _parse_autogen(self, content: str, graph: WorkflowGraph) -> WorkflowGraph:
        """Parse AutoGen workflow.

        Args:
            content: Source code.
            graph: Graph to populate.

        Returns:
            Populated graph.
        """
        # Find AssistantAgent definitions
        assistant_pattern = re.compile(
            r"(\w+)\s*=\s*AssistantAgent\s*\(\s*"
            r"(?:name\s*=\s*)?['\"]([^'\"]+)['\"]",
            re.MULTILINE,
        )

        for match in assistant_pattern.finditer(content):
            var_name = match.group(1)
            agent_name = match.group(2)

            node = WorkflowNode(
                id=var_name,
                name=agent_name,
                node_type="assistant_agent",
                role=AgentRole.EXECUTOR,
                metadata={"framework": "autogen"},
            )
            graph.nodes.append(node)

        # Find UserProxyAgent definitions
        proxy_pattern = re.compile(
            r"(\w+)\s*=\s*UserProxyAgent\s*\(\s*"
            r"(?:name\s*=\s*)?['\"]([^'\"]+)['\"]",
            re.MULTILINE,
        )

        for match in proxy_pattern.finditer(content):
            var_name = match.group(1)
            agent_name = match.group(2)

            node = WorkflowNode(
                id=var_name,
                name=agent_name,
                node_type="user_proxy_agent",
                role=AgentRole.ORCHESTRATOR,
                metadata={"framework": "autogen"},
            )
            graph.nodes.append(node)
            graph.entry_points.append(var_name)

        # Find GroupChat for agent interactions
        groupchat_pattern = re.compile(
            r"GroupChat\s*\(\s*.*?agents\s*=\s*\[(.*?)\]",
            re.MULTILINE | re.DOTALL,
        )

        groupchat_match = groupchat_pattern.search(content)
        if groupchat_match:
            agents_str = groupchat_match.group(1)
            agent_refs = re.findall(r"(\w+)", agents_str)

            # In GroupChat, any agent can talk to any other
            for i, agent1 in enumerate(agent_refs):
                for agent2 in agent_refs[i + 1:]:
                    edge = WorkflowEdge(
                        source=agent1,
                        target=agent2,
                        edge_type="bidirectional",
                    )
                    graph.edges.append(edge)

        return graph

    def _parse_generic(self, content: str, graph: WorkflowGraph) -> WorkflowGraph:
        """Parse generic workflow patterns.

        Args:
            content: Source code.
            graph: Graph to populate.

        Returns:
            Populated graph with generic nodes.
        """
        # Look for common agent patterns
        agent_patterns = [
            (r"(\w*[Aa]gent\w*)\s*=", "agent"),
            (r"class\s+(\w*[Aa]gent\w*)", "agent"),
            (r"(\w+)\s*=\s*\w+Agent\(", "agent"),
        ]

        for pattern, node_type in agent_patterns:
            for match in re.finditer(pattern, content):
                name = match.group(1)
                if not any(n.id == name for n in graph.nodes):
                    node = WorkflowNode(
                        id=name,
                        name=name,
                        node_type=node_type,
                    )
                    graph.nodes.append(node)

        return graph

    def _infer_agent_role(self, role_name: str) -> AgentRole:
        """Infer agent role from name.

        Args:
            role_name: Role name or description.

        Returns:
            Inferred AgentRole.
        """
        role_lower = role_name.lower()

        if any(k in role_lower for k in ["orchestrat", "manag", "lead"]):
            return AgentRole.ORCHESTRATOR
        if any(k in role_lower for k in ["plan", "architect"]):
            return AgentRole.PLANNER
        if any(k in role_lower for k in ["execut", "run", "perform"]):
            return AgentRole.EXECUTOR
        if any(k in role_lower for k in ["review", "check", "valid"]):
            return AgentRole.REVIEWER
        if any(k in role_lower for k in ["research", "search", "find"]):
            return AgentRole.RESEARCHER
        if any(k in role_lower for k in ["code", "develop", "program"]):
            return AgentRole.CODER
        if any(k in role_lower for k in ["write", "author", "content"]):
            return AgentRole.WRITER
        if any(k in role_lower for k in ["tool", "function"]):
            return AgentRole.TOOL_USER

        return AgentRole.CUSTOM

    def _analyze_node(
        self,
        node: WorkflowNode,
        graph: WorkflowGraph,
    ) -> Iterator[WorkflowFinding]:
        """Analyze a workflow node.

        Args:
            node: Node to analyze.
            graph: Parent graph.

        Yields:
            Security findings.
        """
        # Check description and config for risk patterns
        text_to_check = f"{node.name} {node.description} {str(node.config)}"

        for risk in self._risk_patterns:
            if risk["compiled"].search(text_to_check):
                yield WorkflowFinding(
                    category=risk["category"],
                    severity=risk["severity"],
                    title=risk["title"],
                    description=risk["description"],
                    node_id=node.id,
                    evidence={"node_name": node.name, "text_matched": text_to_check[:200]},
                    remediation=f"Review and restrict {node.name} capabilities",
                )

        # Check for nodes with many tools
        if len(node.tools) > 10:
            yield WorkflowFinding(
                category=WorkflowRiskCategory.EXCESSIVE_PERMISSIONS,
                severity=Severity.MEDIUM,
                title=f"Agent has many tools: {len(node.tools)}",
                description="Agent with many tools increases attack surface",
                node_id=node.id,
                evidence={"tool_count": len(node.tools), "tools": node.tools},
                remediation="Limit agent tools to those strictly necessary",
            )

        # Check for dangerous tool patterns
        dangerous_tools = [
            "exec", "eval", "shell", "cmd", "system", "file_write",
            "delete", "rm", "sql", "query",
        ]
        for tool in node.tools:
            tool_lower = tool.lower()
            if any(dt in tool_lower for dt in dangerous_tools):
                yield WorkflowFinding(
                    category=WorkflowRiskCategory.UNVALIDATED_TOOL_USE,
                    severity=Severity.HIGH,
                    title=f"Potentially dangerous tool: {tool}",
                    description="Tool may allow unsafe operations",
                    node_id=node.id,
                    evidence={"tool": tool},
                    remediation="Validate inputs and restrict tool capabilities",
                )

    def _analyze_edge(
        self,
        edge: WorkflowEdge,
        graph: WorkflowGraph,
    ) -> Iterator[WorkflowFinding]:
        """Analyze a workflow edge.

        Args:
            edge: Edge to analyze.
            graph: Parent graph.

        Yields:
            Security findings.
        """
        source_node = graph.get_node(edge.source)
        target_node = graph.get_node(edge.target)

        # Check for data flow between untrusted nodes
        if edge.data_flow:
            sensitive_data = ["password", "secret", "key", "token", "credential"]
            for data in edge.data_flow:
                if any(s in data.lower() for s in sensitive_data):
                    yield WorkflowFinding(
                        category=WorkflowRiskCategory.DATA_FLOW_LEAK,
                        severity=Severity.HIGH,
                        title=f"Sensitive data flows between agents",
                        description=f"Data '{data}' flows from {edge.source} to {edge.target}",
                        edge_id=f"{edge.source}->{edge.target}",
                        evidence={"data_flow": edge.data_flow},
                        remediation="Encrypt or redact sensitive data in transit",
                    )

        # Check for bidirectional edges (potential loop)
        if edge.edge_type == "bidirectional":
            yield WorkflowFinding(
                category=WorkflowRiskCategory.RECURSIVE_LOOP,
                severity=Severity.LOW,
                title="Bidirectional agent communication",
                description=f"Agents {edge.source} and {edge.target} can communicate both ways",
                edge_id=f"{edge.source}<->{edge.target}",
                remediation="Ensure conversation limits are in place",
            )

    def _check_structural_issues(
        self,
        graph: WorkflowGraph,
    ) -> Iterator[WorkflowFinding]:
        """Check for structural issues in the graph.

        Args:
            graph: Graph to check.

        Yields:
            Security findings.
        """
        # Check for no entry points
        if not graph.entry_points:
            yield WorkflowFinding(
                category=WorkflowRiskCategory.UNRESTRICTED_AGENT,
                severity=Severity.LOW,
                title="No clear entry point",
                description="Workflow has no defined entry point",
                remediation="Define explicit entry point for the workflow",
            )

        # Check for isolated nodes
        connected_nodes = set()
        for edge in graph.edges:
            connected_nodes.add(edge.source)
            connected_nodes.add(edge.target)

        for node in graph.nodes:
            if node.id not in connected_nodes and len(graph.nodes) > 1:
                yield WorkflowFinding(
                    category=WorkflowRiskCategory.UNRESTRICTED_AGENT,
                    severity=Severity.LOW,
                    title=f"Isolated agent: {node.name}",
                    description="Agent is not connected to the workflow",
                    node_id=node.id,
                    remediation="Connect agent to workflow or remove if unused",
                )

        # Check for cycles (potential infinite loops)
        cycles = self._find_cycles(graph)
        for cycle in cycles:
            yield WorkflowFinding(
                category=WorkflowRiskCategory.RECURSIVE_LOOP,
                severity=Severity.MEDIUM,
                title="Cycle detected in workflow",
                description=f"Workflow contains a cycle: {' -> '.join(cycle)}",
                evidence={"cycle": cycle},
                attack_path=cycle,
                remediation="Add termination conditions or break the cycle",
            )

        # Check for missing human oversight in autonomous workflows
        has_human_node = any(
            "human" in n.name.lower() or "user" in n.name.lower()
            for n in graph.nodes
        )

        if not has_human_node and len(graph.nodes) > 2:
            yield WorkflowFinding(
                category=WorkflowRiskCategory.MISSING_HUMAN_OVERSIGHT,
                severity=Severity.MEDIUM,
                title="No human-in-the-loop detected",
                description="Workflow appears fully autonomous without human oversight",
                remediation="Add human approval step for critical actions",
            )

    def _find_cycles(self, graph: WorkflowGraph) -> list[list[str]]:
        """Find cycles in the graph using DFS.

        Args:
            graph: Graph to search.

        Returns:
            List of cycles (each cycle is a list of node IDs).
        """
        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()

        def dfs(node_id: str, path: list[str]) -> None:
            visited.add(node_id)
            rec_stack.add(node_id)
            path.append(node_id)

            for edge in graph.get_outgoing_edges(node_id):
                if edge.target not in visited:
                    dfs(edge.target, path.copy())
                elif edge.target in rec_stack:
                    # Found cycle
                    cycle_start = path.index(edge.target)
                    cycle = path[cycle_start:] + [edge.target]
                    cycles.append(cycle)

            rec_stack.remove(node_id)

        for node in graph.nodes:
            if node.id not in visited:
                dfs(node.id, [])

        return cycles

    def _identify_attack_paths(
        self,
        graph: WorkflowGraph,
    ) -> Iterator[WorkflowFinding]:
        """Identify potential attack paths through the workflow.

        Args:
            graph: Graph to analyze.

        Yields:
            Attack path findings.
        """
        # Look for paths from entry to dangerous nodes
        dangerous_nodes = [
            n for n in graph.nodes
            if any(d in n.name.lower() for d in ["exec", "shell", "admin", "root"])
            or any(d in t.lower() for d in ["exec", "shell", "file_write"] for t in n.tools)
        ]

        for entry in graph.entry_points:
            for dangerous in dangerous_nodes:
                path = self._find_path(graph, entry, dangerous.id)
                if path and len(path) > 1:
                    yield WorkflowFinding(
                        category=WorkflowRiskCategory.PRIVILEGE_ESCALATION,
                        severity=Severity.HIGH,
                        title=f"Attack path to dangerous agent: {dangerous.name}",
                        description=f"Path exists from entry to agent with dangerous capabilities",
                        node_id=dangerous.id,
                        evidence={"path_length": len(path)},
                        attack_path=path,
                        remediation="Add validation checkpoints along the path",
                    )

    def _find_path(
        self,
        graph: WorkflowGraph,
        start: str,
        end: str,
    ) -> list[str] | None:
        """Find path between two nodes using BFS.

        Args:
            graph: Graph to search.
            start: Start node ID.
            end: End node ID.

        Returns:
            Path as list of node IDs, or None if no path.
        """
        if start == end:
            return [start]

        visited = {start}
        queue = [(start, [start])]

        while queue:
            node, path = queue.pop(0)

            for edge in graph.get_outgoing_edges(node):
                if edge.target == end:
                    return path + [end]

                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge.target]))

        return None
