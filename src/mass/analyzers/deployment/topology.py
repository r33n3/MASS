"""Deployment topology graph.

Builds a structured node-edge graph representing the AI deployment
architecture.  Nodes represent components (AI agents, models, databases,
cloud services, tools) and edges represent connections between them
(data flows, API calls, tool invocations).

The topology is built from a DeploymentManifest and EnvironmentProfile
produced during the discovery phase.
"""

import logging
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node and edge types
# ---------------------------------------------------------------------------

NODE_TYPES = {
    "ai_agent",
    "model_provider",
    "database",
    "cloud_service",
    "mcp_server",
    "tool",
    "trigger",
    "api_service",
    "memory",
    "vector_store",
}

EDGE_TYPES = {
    "data_flow",
    "auth",
    "tool_call",
    "api_call",
    "model_query",
}

# Icon hints for dashboard rendering (CSS class or emoji reference)
_ICON_HINTS: dict[str, str] = {
    "ai_agent": "agent",
    "model_provider": "model",
    "database": "database",
    "cloud_service": "cloud",
    "mcp_server": "mcp",
    "tool": "tool",
    "trigger": "trigger",
    "api_service": "api",
    "memory": "memory",
    "vector_store": "vector",
}

# Provider icon hints for dashboard
_PROVIDER_ICONS: dict[str, str] = {
    "aws": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "openai": "openai",
    "anthropic": "anthropic",
    "google_ai": "google",
    "ollama": "ollama",
    "local": "local",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TopologyNode:
    """A node in the deployment topology graph."""

    id: str
    type: str          # from NODE_TYPES
    name: str
    provider: str | None = None
    icon_hint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "provider": self.provider,
            "icon_hint": self.icon_hint,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TopologyNode":
        return cls(
            id=data["id"],
            type=data["type"],
            name=data["name"],
            provider=data.get("provider"),
            icon_hint=data.get("icon_hint", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TopologyEdge:
    """An edge connecting two nodes in the topology graph."""

    id: str
    source: str        # node ID
    target: str        # node ID
    edge_type: str     # from EDGE_TYPES
    label: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type,
            "label": self.label,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TopologyEdge":
        return cls(
            id=data["id"],
            source=data["source"],
            target=data["target"],
            edge_type=data["edge_type"],
            label=data.get("label", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class DeploymentTopology:
    """Complete deployment topology graph."""

    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)

    def add_node(self, node: TopologyNode) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: TopologyEdge) -> None:
        self.edges.append(edge)

    def get_node(self, node_id: str) -> TopologyNode | None:
        return next((n for n in self.nodes if n.id == node_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeploymentTopology":
        nodes = [TopologyNode.from_dict(n) for n in data.get("nodes", [])]
        edges = [TopologyEdge.from_dict(e) for e in data.get("edges", [])]
        return cls(nodes=nodes, edges=edges)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def _make_id(prefix: str = "node") -> str:
    return f"{prefix}_{uuid4().hex[:8]}"


class TopologyBuilder:
    """Builds a deployment topology from manifest + environment data.

    The builder creates nodes for each discovered component and infers
    edges based on the relationships between them.
    """

    def build(self, manifest: Any, env: Any) -> DeploymentTopology:
        """Build topology from a DeploymentManifest and EnvironmentProfile.

        Args:
            manifest: DeploymentManifest instance.
            env: EnvironmentProfile instance.

        Returns:
            DeploymentTopology graph.
        """
        topo = DeploymentTopology()

        # 1. Root: AI Agent node (represents the deployment itself)
        agent_id = _make_id("agent")
        topo.add_node(TopologyNode(
            id=agent_id,
            type="ai_agent",
            name=manifest.name or "AI Agent",
            provider=env.cloud_provider if env.cloud_provider != "unknown" else None,
            icon_hint=_ICON_HINTS["ai_agent"],
            metadata={
                "components": manifest.component_count,
                "instructions": manifest.instruction_count,
            },
        ))

        # 2. Model provider nodes
        self._add_model_nodes(topo, manifest, env, agent_id)

        # 3. MCP server nodes
        self._add_mcp_nodes(topo, manifest, agent_id)

        # 4. Database nodes
        self._add_database_nodes(topo, env, agent_id)

        # 5. Cloud service nodes
        self._add_cloud_service_nodes(topo, env, agent_id)

        # 6. Memory / vector store nodes
        self._add_memory_nodes(topo, env, agent_id)

        logger.info(
            "Built topology: %d nodes, %d edges",
            len(topo.nodes), len(topo.edges),
        )

        return topo

    def _add_model_nodes(
        self, topo: DeploymentTopology, manifest: Any, env: Any, agent_id: str
    ) -> None:
        """Add model provider nodes from manifest model configs."""
        seen_providers: set[str] = set()

        for config in manifest.model_configs:
            provider = config.provider.lower()
            model_name = config.model_name or "unknown"

            # Deduplicate by provider+model
            key = f"{provider}:{model_name}"
            if key in seen_providers:
                continue
            seen_providers.add(key)

            node_id = _make_id("model")
            topo.add_node(TopologyNode(
                id=node_id,
                type="model_provider",
                name=f"{provider.title()} - {model_name}",
                provider=provider,
                icon_hint=_PROVIDER_ICONS.get(provider, _ICON_HINTS["model_provider"]),
                metadata={
                    "model_name": model_name,
                    "endpoint": config.endpoint,
                    "api_key_env": config.api_key_env,
                },
            ))

            topo.add_edge(TopologyEdge(
                id=_make_id("edge"),
                source=agent_id,
                target=node_id,
                edge_type="model_query",
                label=f"query {model_name}",
            ))

        # Fallback: if no model configs but env has a model provider
        if not manifest.model_configs and env.model_provider:
            node_id = _make_id("model")
            topo.add_node(TopologyNode(
                id=node_id,
                type="model_provider",
                name=env.model_provider.replace("_", " ").title(),
                provider=env.model_provider,
                icon_hint=_PROVIDER_ICONS.get(
                    env.model_provider, _ICON_HINTS["model_provider"]
                ),
                metadata={"model_name": env.model_name},
            ))
            topo.add_edge(TopologyEdge(
                id=_make_id("edge"),
                source=agent_id,
                target=node_id,
                edge_type="model_query",
                label="query",
            ))

    def _add_mcp_nodes(
        self, topo: DeploymentTopology, manifest: Any, agent_id: str
    ) -> None:
        """Add MCP server nodes."""
        for mcp in manifest.mcp_servers:
            mcp_id = _make_id("mcp")
            server_name = mcp.server_url or "MCP Server"
            # Use last segment of URL as display name
            if "/" in server_name:
                server_name = server_name.rsplit("/", 1)[-1]

            topo.add_node(TopologyNode(
                id=mcp_id,
                type="mcp_server",
                name=server_name,
                icon_hint=_ICON_HINTS["mcp_server"],
                metadata={
                    "url": mcp.server_url,
                    "transport": mcp.transport,
                    "auth_method": mcp.auth_method,
                    "tools": mcp.tools,
                },
            ))

            topo.add_edge(TopologyEdge(
                id=_make_id("edge"),
                source=agent_id,
                target=mcp_id,
                edge_type="tool_call",
                label="tools",
            ))

            # Add individual tool nodes from MCP if tools are listed
            for tool_name in mcp.tools[:10]:  # Cap at 10 to avoid clutter
                tool_id = _make_id("tool")
                topo.add_node(TopologyNode(
                    id=tool_id,
                    type="tool",
                    name=tool_name,
                    icon_hint=_ICON_HINTS["tool"],
                ))

                topo.add_edge(TopologyEdge(
                    id=_make_id("edge"),
                    source=mcp_id,
                    target=tool_id,
                    edge_type="tool_call",
                    label=tool_name,
                ))

    def _add_database_nodes(
        self, topo: DeploymentTopology, env: Any, agent_id: str
    ) -> None:
        """Add database nodes from environment detection."""
        # Separate vector stores from regular databases
        vector_stores = {"chromadb", "pinecone", "qdrant", "weaviate", "faiss", "pgvector"}

        for db in env.databases:
            is_vector = db in vector_stores
            node_type = "vector_store" if is_vector else "database"

            node_id = _make_id("db")
            topo.add_node(TopologyNode(
                id=node_id,
                type=node_type,
                name=db.replace("_", " ").title(),
                icon_hint=_ICON_HINTS.get(node_type, "database"),
                metadata={"db_type": db},
            ))

            edge_label = "vector search" if is_vector else "data"
            topo.add_edge(TopologyEdge(
                id=_make_id("edge"),
                source=agent_id,
                target=node_id,
                edge_type="data_flow",
                label=edge_label,
            ))

    def _add_cloud_service_nodes(
        self, topo: DeploymentTopology, env: Any, agent_id: str
    ) -> None:
        """Add cloud service nodes."""
        # Skip generic SDK entries, only add specific services
        skip_types = {"sdk"}

        for svc in env.cloud_services:
            if svc.service_type in skip_types:
                continue

            node_id = _make_id("cloud")
            display_name = (
                f"{svc.provider.upper()} {svc.service_type.replace('_', ' ').title()}"
            )

            topo.add_node(TopologyNode(
                id=node_id,
                type="cloud_service",
                name=display_name,
                provider=svc.provider,
                icon_hint=_PROVIDER_ICONS.get(svc.provider, _ICON_HINTS["cloud_service"]),
                metadata={
                    "service_type": svc.service_type,
                    "resource_name": svc.resource_name,
                },
            ))

            topo.add_edge(TopologyEdge(
                id=_make_id("edge"),
                source=agent_id,
                target=node_id,
                edge_type="api_call",
                label=svc.service_type.replace("_", " "),
            ))

    def _add_memory_nodes(
        self, topo: DeploymentTopology, env: Any, agent_id: str
    ) -> None:
        """Add memory nodes if Redis or similar is detected as memory store."""
        # Check if Redis is used (common as chat memory / session store)
        memory_dbs = {"redis"}
        for db in env.databases:
            if db in memory_dbs:
                node_id = _make_id("memory")
                topo.add_node(TopologyNode(
                    id=node_id,
                    type="memory",
                    name=f"{db.title()} Memory",
                    icon_hint=_ICON_HINTS["memory"],
                    metadata={"backend": db},
                ))

                topo.add_edge(TopologyEdge(
                    id=_make_id("edge"),
                    source=agent_id,
                    target=node_id,
                    edge_type="data_flow",
                    label="chat memory",
                ))
