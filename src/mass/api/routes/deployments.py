"""Deployment endpoints.

CRUD operations for AI deployments, plus topology graph management.
"""

import json
import logging
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status

from mass.api.dependencies import (
    CurrentTenantDep,
    DeploymentRepo,
    PaginationDep,
)
from mass.api.schemas.deployment import (
    DeploymentCreate,
    DeploymentUpdate,
    DeploymentResponse,
    DeploymentListResponse,
    ComponentResponse,
    MCPServerConfig,
)
from mass.api.schemas.topology import (
    TopologyResponse,
    TopologyUpdate,
    TopologyNodeUpdate,
    TopologyNodeSchema,
    TopologyEdgeSchema,
    TopologyImport,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.storage.models.deployment import Deployment

logger = logging.getLogger(__name__)

router = APIRouter()


def _parse_meta(deployment: Deployment) -> dict:
    """Parse the meta JSON column into a dict."""
    if deployment.meta:
        try:
            return json.loads(deployment.meta)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _deployment_to_response(deployment: Deployment, include_components: bool = False) -> DeploymentResponse:
    """Convert a deployment model to response schema.

    Reconstructs API schema fields from database model:
    - version, tags, source_type, model/MCP config extracted from meta JSON
    - source_branch mapped back to source_ref
    """
    components = None
    if include_components and hasattr(deployment, "components") and deployment.components:
        components = [
            ComponentResponse(
                id=c.id,
                name=c.name,
                component_type=c.component_type,
                description=c.description,
                file_path=c.file_path,
                line_start=c.line_start,
                line_end=c.line_end,
                model_provider=c.model_provider,
                model_name=c.model_name,
                mcp_server_url=c.mcp_server_url,
                created_at=c.created_at,
                updated_at=c.updated_at,
            )
            for c in deployment.components
        ]

    meta = _parse_meta(deployment)

    component_count = len(components) if components is not None else 0

    # Reconstruct MCP server configs from meta
    mcp_servers = None
    if meta.get("mcp_servers"):
        mcp_servers = [MCPServerConfig(**s) for s in meta["mcp_servers"]]

    return DeploymentResponse(
        id=deployment.id,
        name=deployment.name,
        description=deployment.description,
        version=meta.get("version"),
        target_type=meta.get("target_type", "deployment"),
        target_files=meta.get("target_files"),
        source_type=meta.get("source_type", "local"),
        source_path=deployment.source_path,
        source_ref=deployment.source_branch,
        is_active=True,
        last_scanned_at=None,
        tags=meta.get("tags"),
        components=components,
        component_count=component_count,
        scan_count=0,
        model_endpoint=meta.get("model_endpoint"),
        model_provider=meta.get("model_provider"),
        model_name=meta.get("model_name"),
        system_prompt=meta.get("system_prompt"),
        mcp_servers=mcp_servers,
        created_at=deployment.created_at,
        updated_at=deployment.updated_at,
    )


@router.get(
    "",
    response_model=DeploymentListResponse,
    summary="List deployments",
    description="List all deployments for the current tenant.",
)
async def list_deployments(
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
    pagination: PaginationDep,
    is_active: bool | None = None,
) -> DeploymentListResponse:
    """List all deployments for the authenticated tenant."""
    filters = {"tenant_id": tenant.tenant_id}
    if is_active is not None:
        filters["is_active"] = is_active

    deployments = await deployment_repo.list(
        offset=pagination.offset,
        limit=pagination.limit,
        **filters,
    )

    total = await deployment_repo.count(**filters)

    items = [_deployment_to_response(d) for d in deployments]

    return DeploymentListResponse(
        items=items,
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=pagination.offset + len(items) < total,
        ),
    )


@router.post(
    "",
    response_model=DeploymentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create deployment",
    description="Create a new deployment to be scanned.",
)
async def create_deployment(
    request: DeploymentCreate,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> DeploymentResponse:
    """Create a new deployment.

    Maps API schema fields to database model fields:
    - version, tags, source_type, model/MCP config stored in meta JSON
    - source_ref mapped to source_branch
    - deployment_type inferred from source_type
    """
    deployment_type_map = {
        "local": "other",
        "git": "other",
        "s3": "other",
        "azure": "other",
        "gcs": "other",
    }
    deployment_type = deployment_type_map.get(request.source_type, "other")

    # Store all extended fields in meta JSON
    meta_data: dict = {}
    if request.target_type and request.target_type != "deployment":
        meta_data["target_type"] = request.target_type.value if hasattr(request.target_type, "value") else request.target_type
    if request.target_files:
        meta_data["target_files"] = request.target_files
    if request.version:
        meta_data["version"] = request.version
    if request.source_type:
        meta_data["source_type"] = request.source_type
    if request.tags:
        meta_data["tags"] = request.tags
    if request.model_endpoint:
        meta_data["model_endpoint"] = request.model_endpoint
    if request.model_provider:
        meta_data["model_provider"] = request.model_provider
    if request.model_name:
        meta_data["model_name"] = request.model_name
    if request.model_api_key:
        meta_data["model_api_key"] = request.model_api_key
    if request.system_prompt:
        meta_data["system_prompt"] = request.system_prompt
    if request.mcp_servers:
        meta_data["mcp_servers"] = [s.model_dump(exclude_none=True) for s in request.mcp_servers]

    deployment = Deployment(
        tenant_id=tenant.tenant_id,
        name=request.name,
        description=request.description,
        deployment_type=deployment_type,
        source_path=request.source_path,
        source_branch=request.source_ref,
        meta=json.dumps(meta_data) if meta_data else None,
    )

    created = await deployment_repo.create(deployment)

    return _deployment_to_response(created)


@router.get(
    "/{deployment_id}",
    response_model=DeploymentResponse,
    summary="Get deployment",
    description="Get details of a specific deployment.",
)
async def get_deployment(
    deployment_id: str,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
    include_components: bool = False,
) -> DeploymentResponse:
    """Get details of a specific deployment."""
    deployment = await deployment_repo.get_with_components(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    return _deployment_to_response(deployment, include_components=include_components)


@router.patch(
    "/{deployment_id}",
    response_model=DeploymentResponse,
    summary="Update deployment",
    description="Update a deployment's metadata.",
)
async def update_deployment(
    deployment_id: str,
    request: DeploymentUpdate,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> DeploymentResponse:
    """Update a deployment.

    DB columns (name, description, source_path, source_branch) updated directly.
    Extended fields (version, tags, model config, MCP config) merged into meta JSON.
    """
    deployment = await deployment_repo.get(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    # Separate DB column updates from meta JSON updates
    db_updates: dict = {}
    if request.name is not None:
        db_updates["name"] = request.name
    if request.description is not None:
        db_updates["description"] = request.description
    if request.source_path is not None:
        db_updates["source_path"] = request.source_path
    if request.source_ref is not None:
        db_updates["source_branch"] = request.source_ref

    # Merge extended fields into existing meta JSON
    meta = _parse_meta(deployment)
    meta_changed = False

    meta_fields = {
        "version": request.version,
        "tags": request.tags,
        "model_endpoint": request.model_endpoint,
        "model_provider": request.model_provider,
        "model_name": request.model_name,
        "model_api_key": request.model_api_key,
        "system_prompt": request.system_prompt,
    }
    for key, value in meta_fields.items():
        if value is not None:
            meta[key] = value
            meta_changed = True

    if request.mcp_servers is not None:
        meta["mcp_servers"] = [s.model_dump(exclude_none=True) for s in request.mcp_servers]
        meta_changed = True

    if meta_changed:
        db_updates["meta"] = json.dumps(meta)

    if db_updates:
        deployment = await deployment_repo.update(deployment, **db_updates)

    return _deployment_to_response(deployment)


@router.delete(
    "/{deployment_id}",
    response_model=SuccessResponse,
    summary="Delete deployment",
    description="Soft-delete a deployment.",
)
async def delete_deployment(
    deployment_id: str,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> SuccessResponse:
    """Delete a deployment (soft delete)."""
    deployment = await deployment_repo.get(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    await deployment_repo.soft_delete(deployment)

    return SuccessResponse(message="Deployment deleted successfully")


@router.get(
    "/{deployment_id}/components",
    response_model=list[ComponentResponse],
    summary="List deployment components",
    description="List all components discovered in a deployment.",
)
async def list_deployment_components(
    deployment_id: str,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> list[ComponentResponse]:
    """List all components in a deployment."""
    deployment = await deployment_repo.get_with_components(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    return [
        ComponentResponse(
            id=c.id,
            name=c.name,
            component_type=c.component_type,
            description=c.description,
            file_path=c.file_path,
            line_start=c.line_start,
            line_end=c.line_end,
            model_provider=c.model_provider,
            model_name=c.model_name,
            mcp_server_url=c.mcp_server_url,
            created_at=c.created_at,
            updated_at=c.updated_at,
        )
        for c in (deployment.components or [])
    ]


# ---------------------------------------------------------------------------
# Topology endpoints
# ---------------------------------------------------------------------------

def _get_topology_from_meta(meta: dict) -> dict:
    """Extract topology graph from deployment meta."""
    return meta.get("topology", {"nodes": [], "edges": []})


def _get_environment_from_meta(meta: dict) -> dict:
    """Extract environment profile from deployment meta."""
    return meta.get("environment", {})


@router.get(
    "/{deployment_id}/topology",
    response_model=TopologyResponse,
    summary="Get deployment topology",
    description="Return the discovered deployment topology graph.",
)
async def get_topology(
    deployment_id: str,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> TopologyResponse:
    """Get the topology graph for a deployment."""
    deployment = await deployment_repo.get(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    meta = _parse_meta(deployment)
    topo = _get_topology_from_meta(meta)
    env = _get_environment_from_meta(meta)

    return TopologyResponse(
        nodes=[TopologyNodeSchema(**n) for n in topo.get("nodes", [])],
        edges=[TopologyEdgeSchema(**e) for e in topo.get("edges", [])],
        environment=env,
    )


@router.put(
    "/{deployment_id}/topology",
    response_model=TopologyResponse,
    summary="Replace deployment topology",
    description="Replace the entire topology graph (user edit or re-import).",
)
async def update_topology(
    deployment_id: str,
    request: TopologyUpdate,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> TopologyResponse:
    """Replace the full topology graph."""
    deployment = await deployment_repo.get(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    meta = _parse_meta(deployment)
    meta["topology"] = {
        "nodes": [n.model_dump() for n in request.nodes],
        "edges": [e.model_dump() for e in request.edges],
    }

    await deployment_repo.update(deployment, meta=json.dumps(meta))

    env = _get_environment_from_meta(meta)
    return TopologyResponse(
        nodes=request.nodes,
        edges=request.edges,
        environment=env,
    )


@router.patch(
    "/{deployment_id}/topology/nodes/{node_id}",
    response_model=TopologyNodeSchema,
    summary="Update topology node",
    description="Update a single node's name, provider, or metadata.",
)
async def update_topology_node(
    deployment_id: str,
    node_id: str,
    request: TopologyNodeUpdate,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> TopologyNodeSchema:
    """Update a single node in the topology graph."""
    deployment = await deployment_repo.get(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    meta = _parse_meta(deployment)
    topo = _get_topology_from_meta(meta)
    nodes = topo.get("nodes", [])

    # Find and update the target node
    target_node = None
    for node in nodes:
        if node.get("id") == node_id:
            target_node = node
            break

    if target_node is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id} not found in topology",
        )

    if request.name is not None:
        target_node["name"] = request.name
    if request.provider is not None:
        target_node["provider"] = request.provider
    if request.icon_hint is not None:
        target_node["icon_hint"] = request.icon_hint
    if request.metadata is not None:
        target_node.setdefault("metadata", {}).update(request.metadata)

    meta["topology"] = topo
    await deployment_repo.update(deployment, meta=json.dumps(meta))

    return TopologyNodeSchema(**target_node)


@router.post(
    "/{deployment_id}/topology/import",
    response_model=TopologyResponse,
    summary="Import topology from external platform",
    description="Import topology from n8n, Make, or generic node/edge JSON.",
)
async def import_topology(
    deployment_id: str,
    request: TopologyImport,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> TopologyResponse:
    """Import topology from an external automation platform."""
    deployment = await deployment_repo.get(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    try:
        nodes, edges = _convert_import(request.format, request.data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    meta = _parse_meta(deployment)
    meta["topology"] = {
        "nodes": [n.model_dump() for n in nodes],
        "edges": [e.model_dump() for e in edges],
    }

    await deployment_repo.update(deployment, meta=json.dumps(meta))

    env = _get_environment_from_meta(meta)
    return TopologyResponse(nodes=nodes, edges=edges, environment=env)


# ---------------------------------------------------------------------------
# Import adapters
# ---------------------------------------------------------------------------

# n8n node types that map to AI-relevant topology node types
_N8N_AI_NODE_MAP: dict[str, str] = {
    "ai_agent": "ai_agent",
    "@n8n/n8n-nodes-langchain.agent": "ai_agent",
    "@n8n/n8n-nodes-langchain.chainllm": "ai_agent",
    "@n8n/n8n-nodes-langchain.lmchatopenai": "model_provider",
    "@n8n/n8n-nodes-langchain.lmchatanthropic": "model_provider",
    "@n8n/n8n-nodes-langchain.lmchatollama": "model_provider",
    "openai": "model_provider",
    "anthropic": "model_provider",
    "@n8n/n8n-nodes-langchain.memorybuffermemory": "memory",
    "@n8n/n8n-nodes-langchain.memoryredischat": "memory",
    "@n8n/n8n-nodes-langchain.vectorstoreinmemory": "vector_store",
    "@n8n/n8n-nodes-langchain.vectorstorepinecone": "vector_store",
    "@n8n/n8n-nodes-langchain.toolcode": "tool",
    "@n8n/n8n-nodes-langchain.toolworkflow": "tool",
    "mcp": "mcp_server",
}

# Fallback: if not AI-related, use a generic type but still include in graph
_N8N_GENERIC_TYPE = "api_service"


def _make_import_id(prefix: str = "node") -> str:
    return f"{prefix}_{uuid4().hex[:8]}"


def _convert_import(
    fmt: str, data: dict
) -> tuple[list[TopologyNodeSchema], list[TopologyEdgeSchema]]:
    """Convert imported data to topology nodes and edges."""
    if fmt == "n8n":
        return _convert_n8n(data)
    elif fmt == "make":
        return _convert_make(data)
    elif fmt == "generic":
        return _convert_generic(data)
    else:
        raise ValueError(f"Unsupported import format: {fmt}")


def _convert_n8n(
    data: dict,
) -> tuple[list[TopologyNodeSchema], list[TopologyEdgeSchema]]:
    """Convert n8n workflow JSON to topology nodes and edges.

    n8n exports have:
      - nodes: [{name, type, position, parameters, ...}]
      - connections: {nodeName: {main: [[{node, type, index}]]}}
    """
    raw_nodes = data.get("nodes", [])
    raw_connections = data.get("connections", {})

    if not raw_nodes:
        raise ValueError("n8n workflow has no nodes")

    nodes: list[TopologyNodeSchema] = []
    edges: list[TopologyEdgeSchema] = []
    name_to_id: dict[str, str] = {}

    for raw in raw_nodes:
        n8n_type = raw.get("type", "")
        node_name = raw.get("name", n8n_type)

        # Determine our topology node type
        topo_type = _N8N_AI_NODE_MAP.get(n8n_type, _N8N_GENERIC_TYPE)

        node_id = _make_import_id("n8n")
        name_to_id[node_name] = node_id

        nodes.append(TopologyNodeSchema(
            id=node_id,
            type=topo_type,
            name=node_name,
            provider=None,
            icon_hint=topo_type,
            metadata={
                "n8n_type": n8n_type,
                "source": "n8n_import",
            },
        ))

    # Build edges from n8n connections
    for source_name, conn_data in raw_connections.items():
        source_id = name_to_id.get(source_name)
        if not source_id:
            continue
        for output_group in conn_data.get("main", []):
            if not output_group:
                continue
            for conn in output_group:
                target_name = conn.get("node", "")
                target_id = name_to_id.get(target_name)
                if target_id:
                    edges.append(TopologyEdgeSchema(
                        id=_make_import_id("edge"),
                        source=source_id,
                        target=target_id,
                        edge_type="data_flow",
                        label="",
                    ))

    return nodes, edges


def _convert_make(
    data: dict,
) -> tuple[list[TopologyNodeSchema], list[TopologyEdgeSchema]]:
    """Convert Make (Integromat) scenario JSON to topology nodes and edges.

    Make scenarios have:
      - flow: [{id, module, mapper, routes, ...}]
    """
    flow = data.get("flow", [])
    if not flow:
        raise ValueError("Make scenario has no flow modules")

    nodes: list[TopologyNodeSchema] = []
    edges: list[TopologyEdgeSchema] = []
    prev_id: str | None = None

    for module in flow:
        module_id = str(module.get("id", ""))
        module_name = module.get("module", module_id)
        display = module.get("metadata", {}).get("designer", {}).get("name", module_name)

        node_id = _make_import_id("make")

        # Determine node type from module name
        topo_type = "api_service"
        lower_name = module_name.lower()
        if "openai" in lower_name or "ai" in lower_name or "llm" in lower_name:
            topo_type = "model_provider"
        elif "database" in lower_name or "sql" in lower_name or "mongo" in lower_name:
            topo_type = "database"
        elif "memory" in lower_name:
            topo_type = "memory"

        nodes.append(TopologyNodeSchema(
            id=node_id,
            type=topo_type,
            name=display,
            metadata={"make_module": module_name, "source": "make_import"},
        ))

        # Linear flow: connect sequential modules
        if prev_id:
            edges.append(TopologyEdgeSchema(
                id=_make_import_id("edge"),
                source=prev_id,
                target=node_id,
                edge_type="data_flow",
                label="",
            ))
        prev_id = node_id

    return nodes, edges


def _convert_generic(
    data: dict,
) -> tuple[list[TopologyNodeSchema], list[TopologyEdgeSchema]]:
    """Convert generic node/edge JSON to topology.

    Expects: {nodes: [...], edges: [...]} with at least id, type, name per node
    and id, source, target, edge_type per edge.
    """
    raw_nodes = data.get("nodes", [])
    raw_edges = data.get("edges", [])

    nodes = []
    for n in raw_nodes:
        if not n.get("id") or not n.get("type") or not n.get("name"):
            raise ValueError("Each node must have id, type, and name fields")
        nodes.append(TopologyNodeSchema(
            id=n["id"],
            type=n["type"],
            name=n["name"],
            provider=n.get("provider"),
            icon_hint=n.get("icon_hint", ""),
            metadata=n.get("metadata", {}),
        ))

    edges = []
    for e in raw_edges:
        if not e.get("id") or not e.get("source") or not e.get("target") or not e.get("edge_type"):
            raise ValueError("Each edge must have id, source, target, and edge_type fields")
        edges.append(TopologyEdgeSchema(
            id=e["id"],
            type=e["edge_type"],
            source=e["source"],
            target=e["target"],
            edge_type=e["edge_type"],
            label=e.get("label", ""),
            metadata=e.get("metadata", {}),
        ))

    return nodes, edges
