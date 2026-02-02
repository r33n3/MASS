"""CrewAI workflow parser.

Parses CrewAI agent crews and task definitions.
"""

import ast
import re
from typing import Any

from mass.analyzers.workflow.analyzer import (
    WorkflowGraph,
    WorkflowNode,
    WorkflowEdge,
    WorkflowFramework,
    AgentRole,
)


class CrewAIParser:
    """Parser for CrewAI workflows.

    Detects and parses:
    - Agent definitions with roles
    - Task assignments
    - Crew compositions
    - Tool configurations
    """

    def parse(self, content: str, graph: WorkflowGraph) -> WorkflowGraph:
        """Parse CrewAI workflow from source code.

        Args:
            content: Python source code.
            graph: Graph to populate.

        Returns:
            Populated graph.
        """
        graph.framework = WorkflowFramework.CREWAI

        # Parse AST for better extraction
        try:
            tree = ast.parse(content)
            self._parse_ast(tree, graph)
        except SyntaxError:
            # Fall back to regex parsing
            self._parse_regex(content, graph)

        return graph

    def _parse_ast(self, tree: ast.AST, graph: WorkflowGraph) -> None:
        """Parse AST for CrewAI components.

        Args:
            tree: AST tree.
            graph: Graph to populate.
        """
        agents: dict[str, WorkflowNode] = {}
        tasks: list[tuple[str, str]] = []  # (task_var, agent_var)
        crew_agents: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        var_name = target.id
                        call_name = self._get_call_name(node.value)

                        if call_name == "Agent":
                            agent_node = self._parse_agent(var_name, node.value)
                            agents[var_name] = agent_node
                            graph.nodes.append(agent_node)

                        elif call_name == "Task":
                            agent_var = self._get_task_agent(node.value)
                            if agent_var:
                                tasks.append((var_name, agent_var))

                        elif call_name == "Crew":
                            crew_agents = self._get_crew_agents(node.value)

        # Create edges based on crew order and tasks
        if crew_agents:
            # Agents execute in crew order
            for i in range(len(crew_agents) - 1):
                if crew_agents[i] in agents and crew_agents[i + 1] in agents:
                    edge = WorkflowEdge(
                        source=crew_agents[i],
                        target=crew_agents[i + 1],
                        edge_type="flow",
                    )
                    graph.edges.append(edge)

            if crew_agents:
                graph.entry_points.append(crew_agents[0])

    def _parse_agent(self, var_name: str, call: ast.Call) -> WorkflowNode:
        """Parse Agent definition.

        Args:
            var_name: Variable name.
            call: Call AST node.

        Returns:
            WorkflowNode for the agent.
        """
        role = var_name
        goal = ""
        backstory = ""
        tools: list[str] = []
        allow_delegation = False

        for keyword in call.keywords:
            if keyword.arg == "role":
                role = self._get_string_value(keyword.value) or role
            elif keyword.arg == "goal":
                goal = self._get_string_value(keyword.value) or ""
            elif keyword.arg == "backstory":
                backstory = self._get_string_value(keyword.value) or ""
            elif keyword.arg == "tools":
                if isinstance(keyword.value, ast.List):
                    for elt in keyword.value.elts:
                        if isinstance(elt, ast.Name):
                            tools.append(elt.id)
            elif keyword.arg == "allow_delegation":
                if isinstance(keyword.value, ast.Constant):
                    allow_delegation = bool(keyword.value.value)

        return WorkflowNode(
            id=var_name,
            name=role,
            node_type="agent",
            role=self._infer_role(role),
            description=goal,
            tools=tools,
            metadata={
                "framework": "crewai",
                "backstory": backstory,
                "allow_delegation": allow_delegation,
            },
        )

    def _get_task_agent(self, call: ast.Call) -> str | None:
        """Get agent variable from Task definition.

        Args:
            call: Call AST node.

        Returns:
            Agent variable name or None.
        """
        for keyword in call.keywords:
            if keyword.arg == "agent":
                if isinstance(keyword.value, ast.Name):
                    return keyword.value.id
        return None

    def _get_crew_agents(self, call: ast.Call) -> list[str]:
        """Get agent list from Crew definition.

        Args:
            call: Call AST node.

        Returns:
            List of agent variable names.
        """
        agents: list[str] = []

        for keyword in call.keywords:
            if keyword.arg == "agents":
                if isinstance(keyword.value, ast.List):
                    for elt in keyword.value.elts:
                        if isinstance(elt, ast.Name):
                            agents.append(elt.id)

        return agents

    def _infer_role(self, role_name: str) -> AgentRole:
        """Infer agent role from role name.

        Args:
            role_name: Role name or description.

        Returns:
            Inferred AgentRole.
        """
        role_lower = role_name.lower()

        if any(k in role_lower for k in ["orchestrat", "manag", "lead", "ceo"]):
            return AgentRole.ORCHESTRATOR
        if any(k in role_lower for k in ["plan", "architect", "strateg"]):
            return AgentRole.PLANNER
        if any(k in role_lower for k in ["execut", "run", "perform", "worker"]):
            return AgentRole.EXECUTOR
        if any(k in role_lower for k in ["review", "check", "qa", "test"]):
            return AgentRole.REVIEWER
        if any(k in role_lower for k in ["research", "search", "analyst"]):
            return AgentRole.RESEARCHER
        if any(k in role_lower for k in ["code", "develop", "program", "engineer"]):
            return AgentRole.CODER
        if any(k in role_lower for k in ["write", "author", "content", "editor"]):
            return AgentRole.WRITER

        return AgentRole.CUSTOM

    def _get_call_name(self, call: ast.Call) -> str:
        """Get the name of a function call.

        Args:
            call: Call AST node.

        Returns:
            Function name.
        """
        if isinstance(call.func, ast.Name):
            return call.func.id
        elif isinstance(call.func, ast.Attribute):
            return call.func.attr
        return ""

    def _get_string_value(self, node: ast.AST) -> str | None:
        """Get string value from AST node.

        Args:
            node: AST node.

        Returns:
            String value or None.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Str):  # Python < 3.8
            return node.s
        return None

    def _parse_regex(self, content: str, graph: WorkflowGraph) -> None:
        """Parse using regex patterns.

        Args:
            content: Source code.
            graph: Graph to populate.
        """
        # Find Agent definitions
        agent_pattern = re.compile(
            r"(\w+)\s*=\s*Agent\s*\(\s*"
            r"(?:role\s*=\s*)?['\"]([^'\"]+)['\"]",
            re.MULTILINE | re.IGNORECASE,
        )

        agents: list[str] = []
        for match in agent_pattern.finditer(content):
            var_name = match.group(1)
            role = match.group(2)

            node = WorkflowNode(
                id=var_name,
                name=role,
                node_type="agent",
                role=self._infer_role(role),
                metadata={"framework": "crewai"},
            )
            graph.nodes.append(node)
            agents.append(var_name)

        # Find Crew definition for order
        crew_pattern = re.compile(
            r"Crew\s*\(\s*.*?agents\s*=\s*\[(.*?)\]",
            re.MULTILINE | re.DOTALL,
        )

        crew_match = crew_pattern.search(content)
        if crew_match:
            agents_str = crew_match.group(1)
            crew_agents = re.findall(r"(\w+)", agents_str)

            # Create sequential edges
            for i in range(len(crew_agents) - 1):
                edge = WorkflowEdge(
                    source=crew_agents[i],
                    target=crew_agents[i + 1],
                    edge_type="flow",
                )
                graph.edges.append(edge)

            if crew_agents:
                graph.entry_points.append(crew_agents[0])
