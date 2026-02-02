"""OpenAI Agents SDK workflow parser.

Parses OpenAI's Agents SDK (formerly Swarm) configurations.
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


class OpenAIAgentsParser:
    """Parser for OpenAI Agents SDK workflows.

    Detects and parses:
    - Agent definitions
    - Function/tool definitions
    - Agent handoffs
    - Runner configurations
    """

    def parse(self, content: str, graph: WorkflowGraph) -> WorkflowGraph:
        """Parse OpenAI Agents SDK workflow from source code.

        Args:
            content: Python source code.
            graph: Graph to populate.

        Returns:
            Populated graph.
        """
        graph.framework = WorkflowFramework.OPENAI_AGENTS

        # Parse AST for better extraction
        try:
            tree = ast.parse(content)
            self._parse_ast(tree, graph)
        except SyntaxError:
            # Fall back to regex parsing
            self._parse_regex(content, graph)

        return graph

    def _parse_ast(self, tree: ast.AST, graph: WorkflowGraph) -> None:
        """Parse AST for OpenAI Agents components.

        Args:
            tree: AST tree.
            graph: Graph to populate.
        """
        agents: dict[str, WorkflowNode] = {}
        functions: dict[str, str] = {}  # function_name -> agent_name

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

                            # Extract functions/tools
                            funcs = self._get_agent_functions(node.value)
                            for f in funcs:
                                functions[f] = var_name

                        elif call_name == "Runner":
                            # Runner is the orchestrator
                            runner_node = WorkflowNode(
                                id=var_name,
                                name="Runner",
                                node_type="runner",
                                role=AgentRole.ORCHESTRATOR,
                                metadata={"framework": "openai_agents"},
                            )
                            graph.nodes.append(runner_node)

        # Look for handoff patterns
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                handoff_target = self._detect_handoff(node)
                if handoff_target:
                    # Find which agent this function belongs to
                    func_name = node.name
                    if func_name in functions:
                        source_agent = functions[func_name]
                        edge = WorkflowEdge(
                            source=source_agent,
                            target=handoff_target,
                            edge_type="handoff",
                        )
                        graph.edges.append(edge)

        # Set entry point to first agent or runner
        if graph.nodes:
            runners = [n for n in graph.nodes if n.node_type == "runner"]
            if runners:
                graph.entry_points.append(runners[0].id)
            else:
                graph.entry_points.append(graph.nodes[0].id)

    def _parse_agent(self, var_name: str, call: ast.Call) -> WorkflowNode:
        """Parse Agent definition.

        Args:
            var_name: Variable name.
            call: Call AST node.

        Returns:
            WorkflowNode for the agent.
        """
        name = var_name
        instructions = ""
        tools: list[str] = []

        for keyword in call.keywords:
            if keyword.arg == "name":
                name = self._get_string_value(keyword.value) or name
            elif keyword.arg == "instructions":
                instructions = self._get_string_value(keyword.value) or ""
            elif keyword.arg == "functions":
                tools = self._get_list_values(keyword.value)
            elif keyword.arg == "tools":
                tools = self._get_list_values(keyword.value)

        return WorkflowNode(
            id=var_name,
            name=name,
            node_type="agent",
            role=AgentRole.EXECUTOR,
            description=instructions[:200] if instructions else "",
            tools=tools,
            metadata={
                "framework": "openai_agents",
                "instructions_length": len(instructions),
            },
        )

    def _get_agent_functions(self, call: ast.Call) -> list[str]:
        """Get function names from Agent definition.

        Args:
            call: Call AST node.

        Returns:
            List of function names.
        """
        functions: list[str] = []

        for keyword in call.keywords:
            if keyword.arg in ("functions", "tools"):
                functions.extend(self._get_list_values(keyword.value))

        return functions

    def _get_list_values(self, node: ast.AST) -> list[str]:
        """Get list of names from AST node.

        Args:
            node: AST node.

        Returns:
            List of names.
        """
        values: list[str] = []

        if isinstance(node, ast.List):
            for elt in node.elts:
                if isinstance(elt, ast.Name):
                    values.append(elt.id)

        return values

    def _detect_handoff(self, func_def: ast.FunctionDef) -> str | None:
        """Detect if a function performs agent handoff.

        Args:
            func_def: Function definition.

        Returns:
            Target agent name or None.
        """
        for node in ast.walk(func_def):
            # Look for return statements that return an Agent
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Name):
                    # Could be returning another agent
                    return node.value.id
                elif isinstance(node.value, ast.Call):
                    # Could be Agent(...) or transfer_to_agent(...)
                    call_name = self._get_call_name(node.value)
                    if call_name in ("Agent", "transfer_to_agent"):
                        # Try to find the agent name
                        for keyword in node.value.keywords:
                            if keyword.arg == "agent":
                                if isinstance(keyword.value, ast.Name):
                                    return keyword.value.id

        return None

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
            r"(?:name\s*=\s*)?['\"]([^'\"]+)['\"]",
            re.MULTILINE,
        )

        agents: list[str] = []
        for match in agent_pattern.finditer(content):
            var_name = match.group(1)
            agent_name = match.group(2)

            node = WorkflowNode(
                id=var_name,
                name=agent_name,
                node_type="agent",
                role=AgentRole.EXECUTOR,
                metadata={"framework": "openai_agents"},
            )
            graph.nodes.append(node)
            agents.append(var_name)

        # Set first agent as entry point
        if agents:
            graph.entry_points.append(agents[0])

        # Look for return statements that might be handoffs
        handoff_pattern = re.compile(
            r"return\s+(\w+)\s*$",
            re.MULTILINE,
        )

        for match in handoff_pattern.finditer(content):
            target = match.group(1)
            if target in agents:
                # This might be a handoff - we'd need more context
                # to determine the source
                pass
