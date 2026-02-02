"""LangChain workflow parser.

Parses LangChain agent configurations and chains.
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


class LangChainParser:
    """Parser for LangChain workflows.

    Detects and parses:
    - AgentExecutor configurations
    - LLMChain definitions
    - Tool configurations
    - Memory components
    """

    def parse(self, content: str, graph: WorkflowGraph) -> WorkflowGraph:
        """Parse LangChain workflow from source code.

        Args:
            content: Python source code.
            graph: Graph to populate.

        Returns:
            Populated graph.
        """
        graph.framework = WorkflowFramework.LANGCHAIN

        # Parse AST for better extraction
        try:
            tree = ast.parse(content)
            self._parse_ast(tree, graph)
        except SyntaxError:
            # Fall back to regex parsing
            self._parse_regex(content, graph)

        return graph

    def _parse_ast(self, tree: ast.AST, graph: WorkflowGraph) -> None:
        """Parse AST for LangChain components.

        Args:
            tree: AST tree.
            graph: Graph to populate.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                self._handle_assignment(node, graph)
            elif isinstance(node, ast.Call):
                self._handle_call(node, graph)

    def _handle_assignment(self, node: ast.Assign, graph: WorkflowGraph) -> None:
        """Handle variable assignments.

        Args:
            node: Assignment node.
            graph: Graph to populate.
        """
        if not node.targets:
            return

        target = node.targets[0]
        if not isinstance(target, ast.Name):
            return

        var_name = target.id

        if isinstance(node.value, ast.Call):
            call = node.value
            func_name = self._get_call_name(call)

            if func_name in ("AgentExecutor", "create_react_agent", "create_openai_functions_agent"):
                self._add_agent_node(var_name, call, graph)
            elif func_name in ("LLMChain", "ConversationChain", "TransformChain"):
                self._add_chain_node(var_name, func_name, call, graph)
            elif func_name.endswith("Tool") or "tool" in func_name.lower():
                self._add_tool_node(var_name, func_name, call, graph)
            elif "Memory" in func_name:
                self._add_memory_node(var_name, func_name, call, graph)

    def _handle_call(self, node: ast.Call, graph: WorkflowGraph) -> None:
        """Handle function calls for tool detection.

        Args:
            node: Call node.
            graph: Graph to populate.
        """
        func_name = self._get_call_name(node)

        # Look for tool decorator
        if func_name == "tool":
            # Find decorated function name
            pass

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

    def _add_agent_node(
        self,
        var_name: str,
        call: ast.Call,
        graph: WorkflowGraph,
    ) -> None:
        """Add an agent node to the graph.

        Args:
            var_name: Variable name.
            call: Call AST node.
            graph: Graph to populate.
        """
        # Extract tools from agent
        tools: list[str] = []
        for keyword in call.keywords:
            if keyword.arg == "tools":
                if isinstance(keyword.value, ast.List):
                    for elt in keyword.value.elts:
                        if isinstance(elt, ast.Name):
                            tools.append(elt.id)

        node = WorkflowNode(
            id=var_name,
            name=var_name,
            node_type="agent",
            role=AgentRole.EXECUTOR,
            tools=tools,
            metadata={
                "framework": "langchain",
                "agent_type": self._get_call_name(call),
            },
        )
        graph.nodes.append(node)
        graph.entry_points.append(var_name)

        # Create edges to tools
        for tool in tools:
            edge = WorkflowEdge(
                source=var_name,
                target=tool,
                edge_type="tool_call",
            )
            graph.edges.append(edge)

    def _add_chain_node(
        self,
        var_name: str,
        chain_type: str,
        call: ast.Call,
        graph: WorkflowGraph,
    ) -> None:
        """Add a chain node to the graph.

        Args:
            var_name: Variable name.
            chain_type: Type of chain.
            call: Call AST node.
            graph: Graph to populate.
        """
        node = WorkflowNode(
            id=var_name,
            name=var_name,
            node_type="chain",
            role=AgentRole.EXECUTOR,
            metadata={
                "framework": "langchain",
                "chain_type": chain_type,
            },
        )
        graph.nodes.append(node)

    def _add_tool_node(
        self,
        var_name: str,
        tool_type: str,
        call: ast.Call,
        graph: WorkflowGraph,
    ) -> None:
        """Add a tool node to the graph.

        Args:
            var_name: Variable name.
            tool_type: Type of tool.
            call: Call AST node.
            graph: Graph to populate.
        """
        # Extract tool name
        tool_name = var_name
        for keyword in call.keywords:
            if keyword.arg == "name":
                if isinstance(keyword.value, ast.Constant):
                    tool_name = keyword.value.value

        node = WorkflowNode(
            id=var_name,
            name=tool_name,
            node_type="tool",
            role=AgentRole.TOOL_USER,
            metadata={
                "framework": "langchain",
                "tool_type": tool_type,
            },
        )
        graph.nodes.append(node)

    def _add_memory_node(
        self,
        var_name: str,
        memory_type: str,
        call: ast.Call,
        graph: WorkflowGraph,
    ) -> None:
        """Add a memory node to the graph.

        Args:
            var_name: Variable name.
            memory_type: Type of memory.
            call: Call AST node.
            graph: Graph to populate.
        """
        node = WorkflowNode(
            id=var_name,
            name=var_name,
            node_type="memory",
            metadata={
                "framework": "langchain",
                "memory_type": memory_type,
            },
        )
        graph.nodes.append(node)

    def _parse_regex(self, content: str, graph: WorkflowGraph) -> None:
        """Parse using regex patterns.

        Args:
            content: Source code.
            graph: Graph to populate.
        """
        # Find AgentExecutor
        agent_pattern = re.compile(
            r"(\w+)\s*=\s*AgentExecutor\s*\(",
            re.MULTILINE,
        )
        for match in agent_pattern.finditer(content):
            var_name = match.group(1)
            node = WorkflowNode(
                id=var_name,
                name=var_name,
                node_type="agent",
                role=AgentRole.EXECUTOR,
                metadata={"framework": "langchain"},
            )
            graph.nodes.append(node)
            graph.entry_points.append(var_name)

        # Find chains
        chain_pattern = re.compile(
            r"(\w+)\s*=\s*(\w*Chain)\s*\(",
            re.MULTILINE,
        )
        for match in chain_pattern.finditer(content):
            var_name = match.group(1)
            chain_type = match.group(2)
            node = WorkflowNode(
                id=var_name,
                name=var_name,
                node_type="chain",
                metadata={
                    "framework": "langchain",
                    "chain_type": chain_type,
                },
            )
            graph.nodes.append(node)
