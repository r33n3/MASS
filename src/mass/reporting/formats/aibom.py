"""AI Bill of Materials (AI-BOM) generator.

Produces a CycloneDX-inspired JSON document cataloguing all AI components
discovered during a MASS scan: models, frameworks, tools, data sources,
system prompts, and infrastructure.
"""

import hashlib
import json
from datetime import datetime
from typing import Any
from uuid import uuid4

from mass.core.findings import Finding


class AIBOMGenerator:
    """Generates an AI Bill of Materials from scan findings and metadata.

    The AI-BOM captures:
    - AI models (name, provider, format, hash)
    - AI frameworks and libraries (with versions from dependency files)
    - Tools/plugins (MCP servers, LangChain tools)
    - Data sources (vector DBs, knowledge bases, RAG pipelines)
    - System prompts (hashed reference for integrity tracking)
    - Infrastructure components (Docker images, K8s configs)
    """

    BOM_FORMAT = "CycloneDX"
    SPEC_VERSION = "1.6"
    TOOL_NAME = "MASS"
    TOOL_VERSION = "0.1.0"

    def generate(
        self,
        findings: list[Finding],
        scan_id: str = "",
        deployment_name: str = "",
        deployment_path: str = "",
        scan_metadata: dict[str, Any] | None = None,
        architecture_map: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate an AI-BOM from scan data.

        Args:
            findings: All findings from the scan.
            scan_id: Scan identifier.
            deployment_name: Name of the scanned deployment.
            deployment_path: Path to the scanned deployment.
            scan_metadata: Extra scan metadata (job results, etc.).
            architecture_map: AI code architecture analysis results.

        Returns:
            CycloneDX-style JSON dict.
        """
        meta = scan_metadata or {}
        arch = architecture_map or {}

        components = []
        dependencies = []
        services = []

        # Extract models
        components.extend(self._extract_models(findings, arch))

        # Extract frameworks/libraries
        components.extend(self._extract_frameworks(findings, arch))

        # Extract tools/plugins
        components.extend(self._extract_tools(findings, arch))

        # Extract data sources (vector DBs, RAG pipelines)
        components.extend(self._extract_data_sources(findings, arch))

        # Extract infrastructure
        components.extend(self._extract_infrastructure(findings))

        # Extract system prompts as metadata
        prompt_refs = self._extract_prompt_references(findings, arch)

        # Build vulnerability summary from findings
        vulnerabilities = self._extract_vulnerabilities(findings)

        bom: dict[str, Any] = {
            "bomFormat": self.BOM_FORMAT,
            "specVersion": self.SPEC_VERSION,
            "serialNumber": f"urn:uuid:{uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "MASS",
                        "name": self.TOOL_NAME,
                        "version": self.TOOL_VERSION,
                    }
                ],
                "component": {
                    "type": "application",
                    "name": deployment_name or "unknown",
                    "bom-ref": f"deployment:{scan_id}",
                    "description": f"AI deployment scanned by MASS (scan: {scan_id})",
                },
                "properties": [
                    {"name": "mass:scan_id", "value": scan_id},
                    {"name": "mass:deployment_path", "value": deployment_path},
                    {"name": "mass:scan_profile", "value": meta.get("profile", "standard")},
                ],
            },
            "components": components,
            "dependencies": dependencies,
            "services": services,
            "vulnerabilities": vulnerabilities,
            "properties": [
                {"name": "mass:prompt_references", "value": json.dumps(prompt_refs)},
                {"name": "mass:findings_count", "value": str(len(findings))},
            ],
        }

        return bom

    def generate_json(self, **kwargs: Any) -> str:
        """Generate AI-BOM as a JSON string."""
        return json.dumps(self.generate(**kwargs), indent=2)

    # ------------------------------------------------------------------
    # Component extraction helpers
    # ------------------------------------------------------------------

    def _extract_models(
        self, findings: list[Finding], arch: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract model components from findings and architecture map."""
        components: list[dict[str, Any]] = []
        seen: set[str] = set()

        # From architecture map
        for mc in arch.get("model_connections", []):
            provider = mc.get("provider", "unknown")
            model_name = mc.get("model_name", "unknown")
            key = f"{provider}/{model_name}"
            if key in seen:
                continue
            seen.add(key)

            components.append({
                "type": "machine-learning-model",
                "bom-ref": f"model:{key}",
                "name": model_name,
                "publisher": provider,
                "properties": [
                    {"name": "mass:provider", "value": provider},
                    {"name": "mass:call_location", "value": mc.get("call_location", "")},
                ],
            })

        # From findings tagged with model file info
        for f in findings:
            if f.component_type and f.component_type.value == "model":
                name = f.component_name or "unknown-model"
                if name in seen:
                    continue
                seen.add(name)
                props = [{"name": "mass:file_path", "value": f.file_path or ""}]
                components.append({
                    "type": "machine-learning-model",
                    "bom-ref": f"model:{name}",
                    "name": name,
                    "properties": props,
                })

        return components

    def _extract_frameworks(
        self, findings: list[Finding], arch: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract AI framework components."""
        components: list[dict[str, Any]] = []
        seen: set[str] = set()

        # Known AI frameworks to look for in findings
        ai_frameworks = {
            "langchain", "llama_index", "llamaindex", "transformers",
            "openai", "anthropic", "huggingface", "sentence_transformers",
            "chromadb", "pinecone", "qdrant", "weaviate", "milvus",
            "torch", "tensorflow", "keras", "fastapi", "flask",
        }

        for f in findings:
            tags = set(f.tags or [])
            meta = f.metadata or {}
            for fw in ai_frameworks:
                if fw in tags or fw in str(f.description).lower():
                    if fw not in seen:
                        seen.add(fw)
                        components.append({
                            "type": "framework",
                            "bom-ref": f"framework:{fw}",
                            "name": fw,
                            "properties": [
                                {"name": "mass:detected_via", "value": "finding_analysis"},
                            ],
                        })

        # From architecture map patterns
        pattern = arch.get("pattern", "")
        if pattern and pattern not in seen:
            seen.add(pattern)
            components.append({
                "type": "framework",
                "bom-ref": f"framework:pattern:{pattern}",
                "name": pattern,
                "description": f"Detected architecture pattern: {pattern}",
            })

        return components

    def _extract_tools(
        self, findings: list[Finding], arch: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract tool/plugin components (MCP servers, etc.)."""
        components: list[dict[str, Any]] = []
        seen: set[str] = set()

        # From architecture map
        for tool in arch.get("tool_definitions", []):
            name = tool.get("name", "unknown")
            if name in seen:
                continue
            seen.add(name)
            components.append({
                "type": "library",
                "bom-ref": f"tool:{name}",
                "name": name,
                "description": tool.get("description", ""),
                "properties": [
                    {"name": "mass:capabilities", "value": ",".join(tool.get("capabilities", []))},
                    {"name": "mass:location", "value": tool.get("location", "")},
                ],
            })

        # From MCP findings
        for f in findings:
            if f.component_type and f.component_type.value == "mcp_server":
                name = f.component_name or "mcp-server"
                if name not in seen:
                    seen.add(name)
                    components.append({
                        "type": "library",
                        "bom-ref": f"tool:mcp:{name}",
                        "name": name,
                        "description": "MCP server tool",
                        "properties": [
                            {"name": "mass:type", "value": "mcp_server"},
                        ],
                    })

        return components

    def _extract_data_sources(
        self, findings: list[Finding], arch: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract data source components (vector DBs, RAG pipelines)."""
        components: list[dict[str, Any]] = []
        seen: set[str] = set()

        # RAG-related findings
        for f in findings:
            tags = set(f.tags or [])
            if "rag" in tags:
                # Try to identify the specific data source
                for ds_name in ["chroma", "pinecone", "qdrant", "weaviate", "milvus", "faiss"]:
                    if ds_name in (f.description or "").lower() or ds_name in str(f.file_path or "").lower():
                        if ds_name not in seen:
                            seen.add(ds_name)
                            components.append({
                                "type": "data",
                                "bom-ref": f"data:vectordb:{ds_name}",
                                "name": ds_name,
                                "description": f"Vector database: {ds_name}",
                                "properties": [
                                    {"name": "mass:type", "value": "vector_database"},
                                ],
                            })

        # Generic RAG pipeline entry if RAG findings exist
        has_rag = any("rag" in (t or "") for f in findings for t in (f.tags or []))
        if has_rag and "rag_pipeline" not in seen:
            seen.add("rag_pipeline")
            components.append({
                "type": "data",
                "bom-ref": "data:rag_pipeline",
                "name": "RAG Pipeline",
                "description": "Retrieval-Augmented Generation pipeline detected",
            })

        return components

    def _extract_infrastructure(
        self, findings: list[Finding]
    ) -> list[dict[str, Any]]:
        """Extract infrastructure components."""
        components: list[dict[str, Any]] = []
        seen: set[str] = set()

        for f in findings:
            if f.component_type and f.component_type.value == "infrastructure":
                name = f.component_name or "infrastructure"
                if name not in seen:
                    seen.add(name)
                    components.append({
                        "type": "container",
                        "bom-ref": f"infra:{name}",
                        "name": name,
                        "properties": [
                            {"name": "mass:file_path", "value": f.file_path or ""},
                        ],
                    })

        return components

    def _extract_prompt_references(
        self, findings: list[Finding], arch: dict[str, Any]
    ) -> list[dict[str, str]]:
        """Extract hashed system prompt references (not content, for integrity)."""
        refs: list[dict[str, str]] = []
        seen: set[str] = set()

        # From architecture map
        for mc in arch.get("model_connections", []):
            src = mc.get("system_prompt_source")
            if src and src not in seen:
                seen.add(src)
                hash_val = hashlib.sha256(src.encode()).hexdigest()[:16]
                refs.append({
                    "source": src,
                    "hash": hash_val,
                    "provider": mc.get("provider", "unknown"),
                })

        # From context findings
        for f in findings:
            if f.component_type and f.component_type.value == "context":
                fp = f.file_path or ""
                if fp and fp not in seen:
                    seen.add(fp)
                    hash_val = hashlib.sha256(fp.encode()).hexdigest()[:16]
                    refs.append({
                        "source": fp,
                        "hash": hash_val,
                    })

        return refs

    def _extract_vulnerabilities(
        self, findings: list[Finding]
    ) -> list[dict[str, Any]]:
        """Convert findings to CycloneDX vulnerability entries."""
        vulns: list[dict[str, Any]] = []

        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }

        for f in findings:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            vuln: dict[str, Any] = {
                "id": f.id or str(uuid4()),
                "source": {"name": "MASS", "url": "https://github.com/r33n3/MASS"},
                "ratings": [
                    {
                        "severity": severity_map.get(sev_val.lower(), "unknown"),
                        "method": "other",
                        "source": {"name": "MASS"},
                    }
                ],
                "description": f.title,
                "detail": f.description or "",
                "recommendation": (
                    f.remediation.summary if f.remediation else ""
                ),
            }

            # Add CWE references
            if f.cwe_ids:
                vuln["cwes"] = [int(c.replace("CWE-", "")) for c in f.cwe_ids if c.startswith("CWE-")]

            # Add affects (component references)
            if f.file_path:
                vuln["affects"] = [{"ref": f.file_path}]

            vulns.append(vuln)

        return vulns
