"""LangGraph workflow parser.

Parses LangGraph state graphs and message graphs.
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


class LangGraphParser:
    """Parser for LangGraph workflows.

    Detects and parses:
    - StateGraph definitions
    - MessageGraph definitions
    - Node additions
    - Edge connections (including conditional)
    - Entry/exit points
    """

    # Special node names in LangGraph
    SPECIAL_NODES = {"START", "END", "__start__", "__end__"}

    def parse(self, content: str, graph: WorkflowGraph) -> WorkflowGraph:
        """Parse LangGraph workflow from source code.

        Args:
            content: Python source code.
            graph: Graph to populate.

        Returns:
            Populated graph.
        """
        graph.framework = WorkflowFramework.LANGGRAPH

        # Parse AST for better extraction
        try:
            tree = ast.parse(content)
            self._parse_ast(tree, content, graph)
        except SyntaxError:
            # Fall back to regex parsing
            self._parse_regex(content, graph)

        return graph

    def _parse_ast(self, tree: ast.AST, content: str, graph: WorkflowGraph) -> None:
        """Parse AST for LangGraph components.

        Args:
            tree: AST tree.
            content: Original source for context.
            graph: Graph to populate.
        """
        # Find graph variable name
        graph_vars: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        call_name = self._get_call_name(node.value)
                        if call_name in ("StateGraph", "MessageGraph"):
                            graph_vars.append(target.id)
                            graph.metadata["graph_type"] = call_name

        # Parse method calls on graph objects
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                self._handle_method_call(node.value, graph_vars, graph)

    def _handle_method_call(
        self,
        call: ast.Call,
        graph_vars: list[str],
        graph: WorkflowGraph,
    ) -> None:
        """Handle method calls on graph objects.

        Args:
            call: Call AST node.
            graph_vars: Known graph variable names.
            graph: Graph to populate.
        """
        if not isinstance(call.func, ast.Attribute):
            return

        method_name = call.func.attr

        # Check if it's a call on a graph variable
        if isinstance(call.func.value, ast.Name):
            obj_name = call.func.value.id
            if obj_name not in graph_vars:
                return

            if method_name == "add_node":
                self._handle_add_node(call, graph)
            elif method_name == "add_edge":
                self._handle_add_edge(call, graph)
            elif method_name == "add_conditional_edges":
                self._handle_conditional_edges(call, graph)
            elif method_name == "set_entry_point":
                self._handle_set_entry_point(call, graph)
            elif method_name == "set_finish_point":
                self._handle_set_finish_point(call, graph)

    def _handle_add_node(self, call: ast.Call, graph: WorkflowGraph) -> None:
        """Handle add_node call.

        Args:
            call: Call AST node.
            graph: Graph to populate.
        """
        if not call.args:
            return

        # First arg is node name
        node_name = self._get_string_value(call.args[0])
        if not node_name or node_name in self.SPECIAL_NODES:
            return

        # Second arg might be function reference
        func_name = None
        if len(call.args) > 1:
            if isinstance(call.args[1], ast.Name):
                func_name = call.args[1].id

        node = WorkflowNode(
            id=node_name,
            name=node_name,
            node_type="node",
            metadata={
                "framework": "langgraph",
                "function": func_name,
            },
        )
        graph.nodes.append(node)

    def _handle_add_edge(self, call: ast.Call, graph: WorkflowGraph) -> None:
        """Handle add_edge call.

        Args:
            call: Call AST node.
            graph: Graph to populate.
        """
        if len(call.args) < 2:
            return

        source = self._get_string_value(call.args[0])
        target = self._get_string_value(call.args[1])

        if not source or not target:
            return

        # Handle special START/END nodes
        if source in self.SPECIAL_NODES:
            if target and target not in self.SPECIAL_NODES:
                graph.entry_points.append(target)
            return

        if target in self.SPECIAL_NODES:
            return

        edge = WorkflowEdge(
            source=source,
            target=target,
            edge_type="flow",
        )
        graph.edges.append(edge)

    def _handle_conditional_edges(
        self,
        call: ast.Call,
        graph: WorkflowGraph,
    ) -> None:
        """Handle add_conditional_edges call.

        Args:
            call: Call AST node.
            graph: Graph to populate.
        """
        if not call.args:
            return

        source = self._get_string_value(call.args[0])
        if not source or source in self.SPECIAL_NODES:
            return

        # Mark source node as having conditional routing
        source_node = graph.get_node(source)
        if source_node:
            source_node.metadata["has_conditional_routing"] = True

        # Try to extract target mapping
        if len(call.args) > 1:
            mapping_arg = call.args[1]
            # Could be a dict or a function reference
            if isinstance(mapping_arg, ast.Dict):
                for key, value in zip(mapping_arg.keys, mapping_arg.values):
                    target = self._get_string_value(value)
                    if target and target not in self.SPECIAL_NODES:
                        condition = self._get_string_value(key) or "condition"
                        edge = WorkflowEdge(
                            source=source,
                            target=target,
                            edge_type="conditional",
                            condition=condition,
                        )
                        graph.edges.append(edge)

    def _handle_set_entry_point(self, call: ast.Call, graph: WorkflowGraph) -> None:
        """Handle set_entry_point call.

        Args:
            call: Call AST node.
            graph: Graph to populate.
        """
        if call.args:
            entry = self._get_string_value(call.args[0])
            if entry and entry not in graph.entry_points:
                graph.entry_points.append(entry)

    def _handle_set_finish_point(self, call: ast.Call, graph: WorkflowGraph) -> None:
        """Handle set_finish_point call.

        Args:
            call: Call AST node.
            graph: Graph to populate.
        """
        if call.args:
            finish = self._get_string_value(call.args[0])
            if finish:
                graph.metadata.setdefault("finish_points", []).append(finish)

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
        elif isinstance(node, ast.Name):
            # Could be a variable reference like START or END
            return node.id
        return None

    def _parse_regex(self, content: str, graph: WorkflowGraph) -> None:
        """Parse using regex patterns.

        Args:
            content: Source code.
            graph: Graph to populate.
        """
        # Find add_node calls
        add_node_pattern = re.compile(
            r"\.add_node\s*\(\s*['\"](\w+)['\"]",
            re.MULTILINE,
        )
        for match in add_node_pattern.finditer(content):
            node_name = match.group(1)
            if node_name not in self.SPECIAL_NODES:
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

            if source in self.SPECIAL_NODES:
                if target not in self.SPECIAL_NODES:
                    graph.entry_points.append(target)
                continue

            if target in self.SPECIAL_NODES:
                continue

            edge = WorkflowEdge(
                source=source,
                target=target,
                edge_type="flow",
            )
            graph.edges.append(edge)
