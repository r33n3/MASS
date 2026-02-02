"""AutoGen workflow parser.

Parses Microsoft AutoGen agent configurations.
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


class AutoGenParser:
    """Parser for AutoGen workflows.

    Detects and parses:
    - AssistantAgent definitions
    - UserProxyAgent definitions
    - GroupChat configurations
    - Agent conversations
    """

    def parse(self, content: str, graph: WorkflowGraph) -> WorkflowGraph:
        """Parse AutoGen workflow from source code.

        Args:
            content: Python source code.
            graph: Graph to populate.

        Returns:
            Populated graph.
        """
        graph.framework = WorkflowFramework.AUTOGEN

        # Parse AST for better extraction
        try:
            tree = ast.parse(content)
            self._parse_ast(tree, graph)
        except SyntaxError:
            # Fall back to regex parsing
            self._parse_regex(content, graph)

        return graph

    def _parse_ast(self, tree: ast.AST, graph: WorkflowGraph) -> None:
        """Parse AST for AutoGen components.

        Args:
            tree: AST tree.
            graph: Graph to populate.
        """
        agents: dict[str, WorkflowNode] = {}
        groupchat_agents: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        var_name = target.id
                        call_name = self._get_call_name(node.value)

                        if call_name == "AssistantAgent":
                            agent_node = self._parse_assistant_agent(var_name, node.value)
                            agents[var_name] = agent_node
                            graph.nodes.append(agent_node)

                        elif call_name == "UserProxyAgent":
                            agent_node = self._parse_user_proxy(var_name, node.value)
                            agents[var_name] = agent_node
                            graph.nodes.append(agent_node)
                            graph.entry_points.append(var_name)

                        elif call_name == "GroupChat":
                            groupchat_agents = self._get_groupchat_agents(node.value)

                        elif call_name == "GroupChatManager":
                            # GroupChatManager orchestrates the group
                            manager_node = WorkflowNode(
                                id=var_name,
                                name="GroupChatManager",
                                node_type="manager",
                                role=AgentRole.ORCHESTRATOR,
                                metadata={"framework": "autogen"},
                            )
                            graph.nodes.append(manager_node)

        # Create edges for GroupChat
        if groupchat_agents:
            # In GroupChat, agents can talk to each other
            for i, agent1 in enumerate(groupchat_agents):
                for agent2 in groupchat_agents[i + 1:]:
                    # Bidirectional communication
                    edge = WorkflowEdge(
                        source=agent1,
                        target=agent2,
                        edge_type="bidirectional",
                    )
                    graph.edges.append(edge)

        # Look for initiate_chat calls to create edges
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Attribute):
                    if node.value.func.attr == "initiate_chat":
                        self._handle_initiate_chat(node.value, graph)

    def _parse_assistant_agent(self, var_name: str, call: ast.Call) -> WorkflowNode:
        """Parse AssistantAgent definition.

        Args:
            var_name: Variable name.
            call: Call AST node.

        Returns:
            WorkflowNode for the agent.
        """
        name = var_name
        system_message = ""
        code_execution = False

        for keyword in call.keywords:
            if keyword.arg == "name":
                name = self._get_string_value(keyword.value) or name
            elif keyword.arg == "system_message":
                system_message = self._get_string_value(keyword.value) or ""
            elif keyword.arg == "code_execution_config":
                code_execution = True

        return WorkflowNode(
            id=var_name,
            name=name,
            node_type="assistant_agent",
            role=AgentRole.EXECUTOR,
            description=system_message[:200] if system_message else "",
            metadata={
                "framework": "autogen",
                "code_execution": code_execution,
            },
        )

    def _parse_user_proxy(self, var_name: str, call: ast.Call) -> WorkflowNode:
        """Parse UserProxyAgent definition.

        Args:
            var_name: Variable name.
            call: Call AST node.

        Returns:
            WorkflowNode for the agent.
        """
        name = var_name
        human_input_mode = "ALWAYS"
        code_execution = False

        for keyword in call.keywords:
            if keyword.arg == "name":
                name = self._get_string_value(keyword.value) or name
            elif keyword.arg == "human_input_mode":
                human_input_mode = self._get_string_value(keyword.value) or "ALWAYS"
            elif keyword.arg == "code_execution_config":
                code_execution = True

        return WorkflowNode(
            id=var_name,
            name=name,
            node_type="user_proxy_agent",
            role=AgentRole.ORCHESTRATOR,
            metadata={
                "framework": "autogen",
                "human_input_mode": human_input_mode,
                "code_execution": code_execution,
            },
        )

    def _get_groupchat_agents(self, call: ast.Call) -> list[str]:
        """Get agent list from GroupChat definition.

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

    def _handle_initiate_chat(self, call: ast.Call, graph: WorkflowGraph) -> None:
        """Handle initiate_chat method call.

        Args:
            call: Call AST node.
            graph: Graph to populate.
        """
        if not isinstance(call.func, ast.Attribute):
            return

        if not isinstance(call.func.value, ast.Name):
            return

        source = call.func.value.id

        # Find recipient argument
        recipient = None
        for keyword in call.keywords:
            if keyword.arg == "recipient":
                if isinstance(keyword.value, ast.Name):
                    recipient = keyword.value.id

        if not recipient and call.args:
            if isinstance(call.args[0], ast.Name):
                recipient = call.args[0].id

        if recipient:
            # Check if edge already exists
            existing = any(
                e.source == source and e.target == recipient
                for e in graph.edges
            )
            if not existing:
                edge = WorkflowEdge(
                    source=source,
                    target=recipient,
                    edge_type="flow",
                )
                graph.edges.append(edge)

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
