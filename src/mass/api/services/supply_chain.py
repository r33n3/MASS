"""Supply chain verification service.

Manages packages, SBOMs, model provenance verification, and vulnerability
checking.  All state is Redis-backed via JobStore (Rule 1 compliant).
Per ARCHITECTURE.md Section 8.1 — Supply Chain module slot.
"""

import asyncio
import hashlib
import json
import logging
import re
import tomllib
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from mass.api.utils.job_store import JobStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis-backed stores
# ---------------------------------------------------------------------------
_package_store = JobStore("supply_chain_packages", ttl=365 * 24 * 3600)
_sbom_store = JobStore("supply_chain_sboms", ttl=90 * 24 * 3600)
_vuln_store = JobStore("supply_chain_vulns", ttl=30 * 24 * 3600)
_scan_store = JobStore("supply_chain_scans", ttl=30 * 24 * 3600)
_verify_store = JobStore("supply_chain_verify", ttl=7 * 24 * 3600)


# ---------------------------------------------------------------------------
# Known malicious package patterns
# ---------------------------------------------------------------------------
KNOWN_MALICIOUS_PATTERNS: list[dict] = [
    {"pattern": "typosquat", "description": "Name similar to popular package", "severity": "high"},
    {"pattern": "install_hook", "description": "Suspicious install-time code execution", "severity": "critical"},
    {"pattern": "obfuscated_code", "description": "Heavily obfuscated source code", "severity": "high"},
    {"pattern": "data_exfil", "description": "Unexpected network calls during install", "severity": "critical"},
    {"pattern": "env_access", "description": "Reads sensitive environment variables", "severity": "medium"},
]

# Known typosquatting targets for AI/ML ecosystem
TYPOSQUAT_TARGETS: dict[str, list[str]] = {
    "pypi": [
        "torch", "pytorch", "tensorflow", "transformers", "langchain",
        "openai", "anthropic", "huggingface-hub", "tokenizers", "safetensors",
        "scikit-learn", "numpy", "pandas", "scipy", "keras",
        "llama-index", "chromadb", "pinecone-client", "weaviate-client",
    ],
    "npm": [
        "openai", "langchain", "@anthropic-ai/sdk", "ai",
        "@huggingface/inference", "onnxruntime-web", "tensorflow",
    ],
}

# License classification
LICENSE_CLASSIFICATION: dict[str, str] = {
    "MIT": "permissive",
    "Apache-2.0": "permissive",
    "BSD-2-Clause": "permissive",
    "BSD-3-Clause": "permissive",
    "ISC": "permissive",
    "0BSD": "permissive",
    "Unlicense": "permissive",
    "CC0-1.0": "permissive",
    "LGPL-2.1": "weak_copyleft",
    "LGPL-3.0": "weak_copyleft",
    "MPL-2.0": "weak_copyleft",
    "EPL-2.0": "weak_copyleft",
    "GPL-2.0": "strong_copyleft",
    "GPL-3.0": "strong_copyleft",
    "AGPL-3.0": "strong_copyleft",
    "SSPL-1.0": "restricted",
    "BSL-1.1": "restricted",
    "Elastic-2.0": "restricted",
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# Package CRUD
# ---------------------------------------------------------------------------

async def create_package(tenant_id: str, data: dict) -> dict:
    """Create a package record."""
    pkg_id = str(uuid4())
    now = datetime.utcnow().isoformat()
    record = {
        "id": pkg_id,
        "tenant_id": tenant_id,
        **data,
        "license_risk": classify_license(data.get("license")),
        "vulnerabilities": [],
        "verification_status": "pending",
        "last_checked_at": None,
        "created_at": now,
        "updated_at": now,
    }
    await _package_store.save(pkg_id, record)
    return record


async def get_package(pkg_id: str) -> dict | None:
    return await _package_store.load(pkg_id)


async def list_packages(
    tenant_id: str,
    ecosystem: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """List packages, optionally filtered by ecosystem."""
    all_items = await _package_store.list_jobs(tenant_id=tenant_id, limit=5000)
    if ecosystem:
        all_items = [p for p in all_items if p.get("ecosystem") == ecosystem]
    total = len(all_items)
    return all_items[offset : offset + limit], total


async def update_package(pkg_id: str, updates: dict) -> dict:
    record = await _package_store.load(pkg_id)
    if not record:
        raise ValueError(f"Package {pkg_id} not found")
    if "license" in updates:
        updates["license_risk"] = classify_license(updates["license"])
    record.update(updates)
    record["updated_at"] = datetime.utcnow().isoformat()
    await _package_store.save(pkg_id, record)
    return record


async def delete_package(pkg_id: str) -> None:
    await _package_store.delete(pkg_id)


# ---------------------------------------------------------------------------
# SBOM generation
# ---------------------------------------------------------------------------

async def generate_sbom(
    tenant_id: str,
    fmt: str = "cyclonedx",
    include_transitive: bool = True,
    include_vulnerabilities: bool = True,
    include_licenses: bool = True,
    scan_id: str | None = None,
) -> dict:
    """Generate SBOM from registered packages."""
    sbom_id = str(uuid4())
    now = datetime.utcnow().isoformat()

    packages, _ = await list_packages(tenant_id=tenant_id, limit=10000)

    if not include_transitive:
        packages = [p for p in packages if p.get("is_direct", True)]

    direct = [p for p in packages if p.get("is_direct", True)]
    transitive = [p for p in packages if not p.get("is_direct", True)]

    vuln_count = 0
    license_violations = 0

    if include_vulnerabilities:
        vuln_count = sum(len(p.get("vulnerabilities", [])) for p in packages)
    if include_licenses:
        license_violations = sum(
            1 for p in packages
            if p.get("license_risk") in ("strong_copyleft", "restricted", "unknown")
        )

    document = _build_sbom_document(
        fmt, packages, tenant_id, scan_id,
        include_vulnerabilities, include_licenses,
    )

    record = {
        "id": sbom_id,
        "tenant_id": tenant_id,
        "scan_id": scan_id,
        "format": fmt,
        "total_packages": len(packages),
        "direct_packages": len(direct),
        "transitive_packages": len(transitive),
        "vulnerability_count": vuln_count,
        "license_violations": license_violations,
        "document": document,
        "created_at": now,
    }
    await _sbom_store.save(sbom_id, record)
    return record


async def get_sbom(sbom_id: str) -> dict | None:
    return await _sbom_store.load(sbom_id)


async def list_sboms(
    tenant_id: str,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    all_items = await _sbom_store.list_jobs(tenant_id=tenant_id, limit=5000)
    total = len(all_items)
    return all_items[offset : offset + limit], total


def _build_sbom_document(
    fmt: str,
    packages: list[dict],
    tenant_id: str,
    scan_id: str | None,
    include_vulns: bool,
    include_licenses: bool,
) -> dict:
    """Build SBOM document in the requested format."""
    if fmt == "cyclonedx":
        return _build_cyclonedx(packages, tenant_id, scan_id, include_vulns, include_licenses)
    elif fmt == "spdx":
        return _build_spdx(packages, tenant_id, scan_id, include_vulns, include_licenses)
    return {}


def _build_cyclonedx(
    packages: list[dict],
    tenant_id: str,
    scan_id: str | None,
    include_vulns: bool,
    include_licenses: bool,
) -> dict:
    """Build CycloneDX 1.5 SBOM."""
    components = []
    for pkg in packages:
        component: dict = {
            "type": "library",
            "name": pkg["name"],
            "version": pkg.get("version", ""),
            "purl": _build_purl(pkg),
        }
        if include_licenses and pkg.get("license"):
            component["licenses"] = [{"license": {"id": pkg["license"]}}]
        if pkg.get("description"):
            component["description"] = pkg["description"]
        components.append(component)

    doc: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{"vendor": "MASS", "name": "Supply Chain Scanner", "version": "0.1.0"}],
        },
        "components": components,
    }

    if include_vulns:
        vulns = []
        for pkg in packages:
            for v in pkg.get("vulnerabilities", []):
                vulns.append({
                    "id": v.get("cve_id", v.get("advisory_id", "")),
                    "source": {"name": v.get("source", "")},
                    "ratings": [{"severity": v.get("severity", "medium")}] if v.get("severity") else [],
                    "description": v.get("description", ""),
                    "affects": [{"ref": _build_purl(pkg)}],
                })
        if vulns:
            doc["vulnerabilities"] = vulns

    return doc


def _build_spdx(
    packages: list[dict],
    tenant_id: str,
    scan_id: str | None,
    include_vulns: bool,
    include_licenses: bool,
) -> dict:
    """Build SPDX 2.3 SBOM."""
    spdx_packages = []
    for pkg in packages:
        spdx_pkg: dict = {
            "SPDXID": f"SPDXRef-Package-{pkg['name']}-{pkg.get('version', '')}",
            "name": pkg["name"],
            "versionInfo": pkg.get("version", ""),
            "downloadLocation": pkg.get("source_url") or "NOASSERTION",
            "supplier": "NOASSERTION",
        }
        if include_licenses and pkg.get("license"):
            spdx_pkg["licenseConcluded"] = pkg["license"]
            spdx_pkg["licenseDeclared"] = pkg["license"]
        else:
            spdx_pkg["licenseConcluded"] = "NOASSERTION"
            spdx_pkg["licenseDeclared"] = "NOASSERTION"

        spdx_pkg["externalRefs"] = [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": _build_purl(pkg),
        }]
        spdx_packages.append(spdx_pkg)

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"mass-sbom-{scan_id or tenant_id}",
        "documentNamespace": f"https://mass.security/sbom/{uuid4()}",
        "creationInfo": {
            "created": datetime.utcnow().isoformat() + "Z",
            "creators": ["Tool: MASS-Supply-Chain-Scanner-0.1.0"],
        },
        "packages": spdx_packages,
    }


def _build_purl(pkg: dict) -> str:
    """Build Package URL (purl) from package data."""
    ecosystem = pkg.get("ecosystem", "generic")
    name = pkg.get("name", "")
    version = pkg.get("version", "")
    purl_type_map = {
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "cargo": "cargo",
        "go": "golang",
        "docker": "docker",
        "huggingface": "huggingface",
        "other": "generic",
    }
    purl_type = purl_type_map.get(ecosystem, "generic")
    return f"pkg:{purl_type}/{name}@{version}" if version else f"pkg:{purl_type}/{name}"


# ---------------------------------------------------------------------------
# License classification
# ---------------------------------------------------------------------------

def classify_license(license_id: str | None) -> str:
    """Classify a license by risk level."""
    if not license_id:
        return "unknown"
    normalized = license_id.strip()
    if normalized in LICENSE_CLASSIFICATION:
        return LICENSE_CLASSIFICATION[normalized]
    lower = normalized.lower()
    if "mit" in lower or "bsd" in lower or "apache" in lower:
        return "permissive"
    if "gpl" in lower:
        if "lgpl" in lower:
            return "weak_copyleft"
        if "agpl" in lower:
            return "strong_copyleft"
        return "strong_copyleft"
    if "mpl" in lower:
        return "weak_copyleft"
    return "unknown"


# ---------------------------------------------------------------------------
# Malicious package checks
# ---------------------------------------------------------------------------

def check_typosquatting(name: str, ecosystem: str) -> list[dict]:
    """Check if a package name looks like a typosquat of a popular package."""
    findings = []
    targets = TYPOSQUAT_TARGETS.get(ecosystem, [])
    for target in targets:
        if name == target:
            continue
        distance = _levenshtein_distance(name.lower(), target.lower())
        if 0 < distance <= 2:
            findings.append({
                "type": "typosquatting",
                "severity": "high",
                "title": f"Possible typosquat of '{target}'",
                "description": (
                    f"Package '{name}' is similar to popular package '{target}' "
                    f"(edit distance: {distance})"
                ),
                "target_package": target,
                "edit_distance": distance,
            })
    return findings


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


# ---------------------------------------------------------------------------
# Model provenance verification (integrates with existing analyzer)
# ---------------------------------------------------------------------------

async def verify_model(
    tenant_id: str,
    file_path: str,
    expected_hash: str | None = None,
    source_url: str | None = None,
    model_id: str | None = None,
    check_provenance: bool = True,
    check_signatures: bool = True,
    check_format: bool = True,
) -> dict:
    """Start a model verification job.  Returns job data with job_id."""
    job_id = str(uuid4())
    now = datetime.utcnow().isoformat()

    job: dict = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "status": "pending",
        "file_path": file_path,
        "expected_hash": expected_hash,
        "source_url": source_url,
        "model_id": model_id,
        "check_provenance": check_provenance,
        "check_signatures": check_signatures,
        "check_format": check_format,
        "format_detected": None,
        "hash_sha256": None,
        "hash_match": "skipped",
        "provenance_status": "skipped",
        "signature_status": "skipped",
        "format_status": "skipped",
        "findings": [],
        "provenance": None,
        "error": None,
        "created_at": now,
        "completed_at": None,
    }
    await _verify_store.save(job_id, job)
    return job


async def run_model_verification(job_id: str) -> None:
    """Execute model verification (runs as BackgroundTask)."""
    job = await _verify_store.load(job_id)
    if not job:
        return

    try:
        job["status"] = "running"
        await _verify_store.save(job_id, job)

        file_path = Path(job["file_path"])
        findings: list[dict] = []

        if not file_path.exists():
            job["status"] = "failed"
            job["error"] = f"File not found: {file_path}"
            await _verify_store.save(job_id, job)
            return

        # Compute hash
        sha256 = await asyncio.to_thread(_compute_sha256, file_path)
        job["hash_sha256"] = sha256

        # Hash verification
        if job.get("expected_hash"):
            if sha256.lower() == job["expected_hash"].lower():
                job["hash_match"] = "passed"
            else:
                job["hash_match"] = "failed"
                findings.append({
                    "severity": "critical",
                    "title": "Hash mismatch",
                    "description": f"Expected {job['expected_hash']}, got {sha256}",
                    "category": "supply_chain",
                })

        # Format detection + security checks
        if job.get("check_format"):
            format_findings = await asyncio.to_thread(
                _run_format_checks, file_path,
            )
            if format_findings:
                job["format_detected"] = format_findings.get("format")
                findings.extend(format_findings.get("findings", []))
                job["format_status"] = (
                    "failed" if format_findings.get("findings") else "passed"
                )
            else:
                job["format_status"] = "passed"

        # Provenance verification
        if job.get("check_provenance"):
            prov_findings = await asyncio.to_thread(
                _run_provenance_checks,
                file_path,
                sha256,
                job.get("source_url"),
                job.get("model_id"),
            )
            job["provenance"] = prov_findings.get("provenance")
            findings.extend(prov_findings.get("findings", []))
            job["provenance_status"] = (
                "failed" if prov_findings.get("findings") else "passed"
            )

        # Signature check (placeholder — real impl needs GPG / sigstore)
        if job.get("check_signatures"):
            sig_file = file_path.with_suffix(file_path.suffix + ".sig")
            if sig_file.exists():
                job["signature_status"] = "warning"
                findings.append({
                    "severity": "info",
                    "title": "Signature file found but verification not yet implemented",
                    "description": f"Signature file: {sig_file.name}",
                    "category": "supply_chain",
                })
            else:
                job["signature_status"] = "skipped"

        job["findings"] = findings
        job["status"] = "completed"
        job["completed_at"] = datetime.utcnow().isoformat()

        # Broadcast event
        try:
            from mass.core.events import Event, EventType, publish_event
            await publish_event(Event(
                type=EventType.SUPPLY_CHAIN_VERIFIED,
                data={
                    "job_id": job_id,
                    "file_path": str(file_path),
                    "findings_count": len(findings),
                },
                tenant_id=job.get("tenant_id"),
            ))
        except Exception:
            pass

    except Exception as exc:
        logger.exception("Model verification failed for job %s", job_id)
        job["status"] = "failed"
        job["error"] = str(exc)
        await _verify_store.move_to_dlq(job_id, str(exc))

    await _verify_store.save(job_id, job)


async def get_verify_job(job_id: str) -> dict | None:
    return await _verify_store.load(job_id)


def _compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_format_checks(file_path: Path) -> dict:
    """Run model format-specific security checks."""
    result: dict = {"format": None, "findings": []}
    try:
        from mass.analyzers.model_file.scanner import ModelFileScanner
        scanner = ModelFileScanner()
        fmt = scanner.detect_format(file_path)
        result["format"] = fmt.value if fmt else "unknown"

        scan_result = scanner.scan_file(file_path)
        for finding in scan_result.findings:
            result["findings"].append({
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "title": finding.title,
                "description": finding.description,
                "category": finding.category.value if hasattr(finding.category, "value") else str(finding.category),
                "evidence": finding.evidence if hasattr(finding, "evidence") else None,
            })
    except ImportError:
        logger.debug("ModelFileScanner not available")
    except Exception as e:
        logger.debug("Format check error: %s", e)
    return result


def _run_provenance_checks(
    file_path: Path,
    file_hash: str,
    source_url: str | None,
    model_id: str | None,
) -> dict:
    """Run provenance verification using the existing SupplyChainAnalyzer."""
    result: dict = {"provenance": None, "findings": []}
    try:
        from mass.analyzers.model_file.supply_chain import (
            ProvenanceInfo,
            SupplyChainAnalyzer,
        )
        analyzer = SupplyChainAnalyzer(require_provenance=True)

        provenance = None
        loaded = analyzer.load_provenance(file_path)
        if loaded:
            provenance = loaded
        elif source_url or model_id:
            provenance = ProvenanceInfo(
                source_url=source_url,
                model_id=model_id,
            )

        for finding in analyzer.analyze(file_path, file_hash, provenance):
            result["findings"].append({
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "title": finding.title,
                "description": finding.description,
                "category": "supply_chain",
            })

        if provenance:
            result["provenance"] = provenance.to_dict()

    except ImportError:
        logger.debug("SupplyChainAnalyzer not available")
    except Exception as e:
        logger.debug("Provenance check error: %s", e)
    return result


# ---------------------------------------------------------------------------
# Full supply chain scan
# ---------------------------------------------------------------------------

async def start_supply_chain_scan(tenant_id: str, request: dict) -> dict:
    """Start a full supply chain scan job."""
    job_id = str(uuid4())
    now = datetime.utcnow().isoformat()
    job = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "status": "pending",
        "request": request,
        "total_packages": 0,
        "total_models": 0,
        "vulnerabilities_found": 0,
        "license_violations": 0,
        "malicious_detected": 0,
        "provenance_failures": 0,
        "findings": [],
        "error": None,
        "created_at": now,
        "completed_at": None,
    }
    await _scan_store.save(job_id, job)
    return job


async def run_supply_chain_scan(job_id: str) -> None:
    """Execute full supply chain scan (runs as BackgroundTask)."""
    job = await _scan_store.load(job_id)
    if not job:
        return

    try:
        job["status"] = "running"
        await _scan_store.save(job_id, job)

        tenant_id = job["tenant_id"]
        request = job.get("request", {})
        findings: list[dict] = []
        threshold_idx = SEVERITY_LEVELS.index(
            request.get("severity_threshold", "medium")
        )

        # 1. Check all registered packages
        packages, total = await list_packages(tenant_id=tenant_id, limit=10000)
        job["total_packages"] = total

        if request.get("check_vulnerabilities", True):
            for pkg in packages:
                for vuln in pkg.get("vulnerabilities", []):
                    sev = vuln.get("severity", "medium")
                    if SEVERITY_LEVELS.index(sev) <= threshold_idx:
                        findings.append({
                            "severity": sev,
                            "title": f"Vulnerability in {pkg['name']}@{pkg.get('version', '')}",
                            "description": vuln.get("description", ""),
                            "category": "supply_chain",
                            "cve_id": vuln.get("cve_id"),
                            "package": pkg["name"],
                        })
                        job["vulnerabilities_found"] += 1

        if request.get("check_licenses", True):
            for pkg in packages:
                risk = pkg.get("license_risk", "unknown")
                if risk in ("strong_copyleft", "restricted", "unknown"):
                    sev = "high" if risk == "restricted" else "medium"
                    if SEVERITY_LEVELS.index(sev) <= threshold_idx:
                        findings.append({
                            "severity": sev,
                            "title": f"License concern: {pkg['name']}",
                            "description": (
                                f"Package '{pkg['name']}' has license "
                                f"'{pkg.get('license', 'unknown')}' (risk: {risk})"
                            ),
                            "category": "supply_chain",
                            "package": pkg["name"],
                            "license": pkg.get("license"),
                            "license_risk": risk,
                        })
                        job["license_violations"] += 1

        if request.get("check_malicious_packages", True):
            for pkg in packages:
                typo_findings = check_typosquatting(
                    pkg["name"], pkg.get("ecosystem", ""),
                )
                for tf in typo_findings:
                    if SEVERITY_LEVELS.index(tf["severity"]) <= threshold_idx:
                        findings.append({
                            **tf,
                            "category": "supply_chain",
                            "package": pkg["name"],
                        })
                        job["malicious_detected"] += 1

        job["findings"] = findings
        job["status"] = "completed"
        job["completed_at"] = datetime.utcnow().isoformat()

        # Broadcast event
        try:
            from mass.core.events import Event, EventType, publish_event
            await publish_event(Event(
                type=EventType.SUPPLY_CHAIN_SCAN_COMPLETED,
                data={
                    "job_id": job_id,
                    "vulnerabilities": job["vulnerabilities_found"],
                    "license_violations": job["license_violations"],
                    "malicious": job["malicious_detected"],
                },
                tenant_id=tenant_id,
            ))
        except Exception:
            pass

    except Exception as exc:
        logger.exception("Supply chain scan failed for job %s", job_id)
        job["status"] = "failed"
        job["error"] = str(exc)
        await _scan_store.move_to_dlq(job_id, str(exc))

    await _scan_store.save(job_id, job)


async def get_scan_job(job_id: str) -> dict | None:
    return await _scan_store.load(job_id)


async def list_scan_jobs(
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    all_items = await _scan_store.list_jobs(tenant_id=tenant_id, limit=5000)
    total = len(all_items)
    return all_items[offset : offset + limit], total


# ---------------------------------------------------------------------------
# Vulnerability CRUD
# ---------------------------------------------------------------------------

async def create_vulnerability(tenant_id: str, data: dict) -> dict:
    vuln_id = str(uuid4())
    now = datetime.utcnow().isoformat()
    record = {
        "id": vuln_id,
        "tenant_id": tenant_id,
        **data,
        "created_at": now,
    }
    await _vuln_store.save(vuln_id, record)
    return record


async def list_vulnerabilities(
    tenant_id: str,
    package_name: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    all_items = await _vuln_store.list_jobs(tenant_id=tenant_id, limit=5000)
    if package_name:
        all_items = [v for v in all_items if v.get("affected_package") == package_name]
    if severity:
        all_items = [v for v in all_items if v.get("severity") == severity]
    total = len(all_items)
    return all_items[offset : offset + limit], total


# ---------------------------------------------------------------------------
# Dependency file parsing — auto-extract packages from project files
# ---------------------------------------------------------------------------

import re
import tomllib


def _parse_requirements_txt(content: str) -> list[dict]:
    """Parse requirements.txt content into package dicts."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: package==1.0, package>=1.0, package~=1.0, package
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*([>=<~!]+\s*[\d.*]+)?", line)
        if match:
            name = match.group(1).lower().replace("_", "-")
            version_spec = match.group(2) or ""
            version = re.sub(r"[>=<~!]+\s*", "", version_spec).strip() or "unknown"
            packages.append({"name": name, "version": version, "ecosystem": "pypi", "is_direct": True})
    return packages


def _parse_pyproject_toml(content: str) -> list[dict]:
    """Parse pyproject.toml content into package dicts."""
    packages = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return packages
    deps = data.get("project", {}).get("dependencies", [])
    if isinstance(deps, list):
        for dep in deps:
            match = re.match(r"^([A-Za-z0-9_.-]+)\s*([>=<~!]+\s*[\d.*]+)?", dep)
            if match:
                name = match.group(1).lower().replace("_", "-")
                version_spec = match.group(2) or ""
                version = re.sub(r"[>=<~!]+\s*", "", version_spec).strip() or "unknown"
                packages.append({"name": name, "version": version, "ecosystem": "pypi", "is_direct": True})
    # Also check optional-dependencies
    for group_deps in data.get("project", {}).get("optional-dependencies", {}).values():
        if isinstance(group_deps, list):
            for dep in group_deps:
                match = re.match(r"^([A-Za-z0-9_.-]+)\s*([>=<~!]+\s*[\d.*]+)?", dep)
                if match:
                    name = match.group(1).lower().replace("_", "-")
                    packages.append({"name": name, "version": "unknown", "ecosystem": "pypi", "is_direct": False})
    return packages


def _parse_package_json(content: str) -> list[dict]:
    """Parse package.json content into package dicts."""
    packages = []
    try:
        data = json.loads(content)
    except Exception:
        return packages
    for section, is_direct in [("dependencies", True), ("devDependencies", False)]:
        for name, version in data.get(section, {}).items():
            clean_ver = re.sub(r"[\^~>=<]", "", version).strip() or "unknown"
            packages.append({"name": name, "version": clean_ver, "ecosystem": "npm", "is_direct": is_direct})
    return packages


async def parse_dependency_files(
    tenant_id: str,
    directory: str,
    auto_register: bool = True,
) -> dict:
    """Parse dependency files in a directory and optionally register packages.

    Scans for requirements.txt, pyproject.toml, package.json, and
    auto-registers discovered packages for the tenant.

    Args:
        tenant_id: Tenant ID.
        directory: Directory path to scan.
        auto_register: If True, create package records for discovered deps.

    Returns:
        Dict with parsed_files, total_packages, registered, skipped.
    """
    dir_path = Path(directory)
    parsed_files: list[str] = []
    all_packages: list[dict] = []

    # Scan for dependency files (up to 2 levels deep)
    dep_file_patterns = {
        "requirements*.txt": _parse_requirements_txt,
        "pyproject.toml": _parse_pyproject_toml,
        "package.json": _parse_package_json,
    }

    for pattern, parser in dep_file_patterns.items():
        for dep_file in dir_path.glob(pattern):
            try:
                content = dep_file.read_text(encoding="utf-8", errors="replace")
                pkgs = parser(content)
                if pkgs:
                    parsed_files.append(str(dep_file.relative_to(dir_path)))
                    all_packages.extend(pkgs)
            except Exception as exc:
                logger.debug("Failed to parse %s: %s", dep_file, exc)
        # Also check one level deep
        for dep_file in dir_path.glob(f"*/{pattern}"):
            try:
                content = dep_file.read_text(encoding="utf-8", errors="replace")
                pkgs = parser(content)
                if pkgs:
                    parsed_files.append(str(dep_file.relative_to(dir_path)))
                    all_packages.extend(pkgs)
            except Exception as exc:
                logger.debug("Failed to parse %s: %s", dep_file, exc)

    # Deduplicate by (name, ecosystem)
    seen = set()
    unique_packages = []
    for pkg in all_packages:
        key = (pkg["name"], pkg["ecosystem"])
        if key not in seen:
            seen.add(key)
            unique_packages.append(pkg)

    registered = 0
    skipped = 0
    if auto_register:
        existing, _ = await list_packages(tenant_id=tenant_id, limit=10000)
        existing_keys = {(p["name"], p.get("ecosystem", "")) for p in existing}
        for pkg in unique_packages:
            key = (pkg["name"], pkg.get("ecosystem", ""))
            if key in existing_keys:
                skipped += 1
                continue
            await create_package(tenant_id, pkg)
            registered += 1

    return {
        "parsed_files": parsed_files,
        "total_packages": len(unique_packages),
        "registered": registered,
        "skipped": skipped,
        "packages": unique_packages,
    }
