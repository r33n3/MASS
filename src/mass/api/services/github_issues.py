"""GitHub issue generation service.

Creates well-formatted GitHub Issues from MASS security findings,
tracks exported issues to avoid duplicates, and supports auto-export.
"""

import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

import httpx

from mass.api.utils.job_store import JobStore

logger = logging.getLogger(__name__)

# Redis-backed stores (Rule 1 compliant)
_config_store = JobStore("github_configs", ttl=365 * 24 * 3600)  # 1 year
_export_store = JobStore("github_exports", ttl=90 * 24 * 3600)   # 90 days

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_EMOJI = {
    "critical": "\U0001f534",  # red circle
    "high": "\U0001f7e0",      # orange circle
    "medium": "\U0001f7e1",    # yellow circle
    "low": "\U0001f535",       # blue circle
    "info": "\u26aa",          # white circle
}


# ---------------------------------------------------------------------------
# Config CRUD
# ---------------------------------------------------------------------------

async def create_config(tenant_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Create a GitHub integration config."""
    config_id = f"ghcfg_{uuid4().hex[:12]}"
    now = datetime.utcnow().isoformat()

    # Mask token for storage response (store real token securely)
    record = {
        "id": config_id,
        "tenant_id": tenant_id,
        **data,
        "total_exported": 0,
        "last_export_at": None,
        "created_at": now,
        "updated_at": now,
    }
    await _config_store.save(config_id, record)
    logger.info("Created GitHub config", extra={"config_id": config_id, "repo": f"{data.get('owner')}/{data.get('repo')}"})
    return record


async def get_config(config_id: str) -> dict[str, Any] | None:
    return await _config_store.load(config_id)


async def list_configs(
    tenant_id: str, limit: int = 50, offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    all_cfgs = await _config_store.list_jobs(tenant_id=tenant_id, limit=1000)
    total = len(all_cfgs)
    return all_cfgs[offset : offset + limit], total


async def update_config(config_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
    record = await _config_store.load(config_id)
    if not record:
        return None
    for k, v in updates.items():
        if v is not None:
            record[k] = v
    record["updated_at"] = datetime.utcnow().isoformat()
    await _config_store.save(config_id, record)
    return record


async def delete_config(config_id: str) -> bool:
    return await _config_store.delete(config_id)


def mask_token(token: str) -> str:
    """Return last 4 characters of a token for display."""
    if len(token) <= 4:
        return "****"
    return f"****{token[-4:]}"


def prepare_response(record: dict[str, Any]) -> dict[str, Any]:
    """Prepare config record for API response (mask token)."""
    result = {**record}
    result["token_last4"] = mask_token(result.pop("token", ""))
    return result


# ---------------------------------------------------------------------------
# Issue formatting
# ---------------------------------------------------------------------------

def format_issue_title(finding: dict[str, Any]) -> str:
    """Format a GitHub Issue title from a finding."""
    severity = (finding.get("severity") or "medium").upper()
    title = finding.get("title") or "Security Finding"
    return f"[{severity}] {title}"


def format_issue_body(finding: dict[str, Any], scan_id: str = "") -> str:
    """Format a GitHub Issue body with full finding details."""
    severity = finding.get("severity", "medium").lower()
    emoji = SEVERITY_EMOJI.get(severity, "")
    parts: list[str] = []

    # Header
    parts.append(f"## {emoji} {finding.get('title', 'Security Finding')}")
    parts.append("")
    parts.append(f"**Severity:** {severity.upper()}")

    if finding.get("category"):
        parts.append(f"**Category:** {finding['category']}")

    if finding.get("confidence"):
        parts.append(f"**Confidence:** {finding['confidence']:.0%}")

    parts.append("")

    # Description
    if finding.get("description"):
        parts.append("### Description")
        parts.append(finding["description"])
        parts.append("")

    # Location
    file_path = finding.get("file_path")
    line_number = finding.get("line_number")
    if file_path:
        loc = f"`{file_path}`"
        if line_number:
            loc += f" (line {line_number})"
        parts.append(f"### Location")
        parts.append(loc)
        parts.append("")

    # Code snippet
    if finding.get("code_snippet"):
        parts.append("### Code Snippet")
        parts.append("```")
        parts.append(finding["code_snippet"])
        parts.append("```")
        parts.append("")

    # Evidence
    if finding.get("evidence"):
        parts.append("### Evidence")
        evidence = finding["evidence"]
        if isinstance(evidence, str):
            parts.append(evidence)
        elif isinstance(evidence, list):
            for e in evidence[:5]:
                if isinstance(e, dict):
                    parts.append(f"- {e.get('description', str(e))}")
                else:
                    parts.append(f"- {e}")
        parts.append("")

    # Remediation
    if finding.get("remediation"):
        parts.append("### Remediation")
        parts.append(finding["remediation"])
        parts.append("")

    # References
    refs = []
    if finding.get("cwe_id"):
        refs.append(f"[CWE-{finding['cwe_id']}](https://cwe.mitre.org/data/definitions/{finding['cwe_id']}.html)")
    if finding.get("owasp_category"):
        refs.append(f"OWASP: {finding['owasp_category']}")
    if finding.get("mitre_technique"):
        refs.append(f"MITRE: {finding['mitre_technique']}")
    if refs:
        parts.append("### References")
        for r in refs:
            parts.append(f"- {r}")
        parts.append("")

    # Footer
    parts.append("---")
    parts.append(f"*Generated by [MASS](https://github.com/r33n3/MASS) — Model & Application Security Suite*")
    if scan_id:
        parts.append(f"*Scan ID: `{scan_id}`*")
    if finding.get("id"):
        parts.append(f"*Finding ID: `{finding['id']}`*")

    return "\n".join(parts)


def build_labels(
    finding: dict[str, Any],
    base_labels: list[str],
    severity_labels: bool = True,
    category_labels: bool = True,
) -> list[str]:
    """Build the label set for a GitHub Issue."""
    labels = list(base_labels)
    if severity_labels and finding.get("severity"):
        labels.append(f"severity:{finding['severity'].lower()}")
    if category_labels and finding.get("category"):
        labels.append(finding["category"].lower().replace(" ", "-"))
    return labels


# ---------------------------------------------------------------------------
# GitHub API interaction
# ---------------------------------------------------------------------------

async def create_github_issue(
    config: dict[str, Any],
    title: str,
    body: str,
    labels: list[str],
) -> dict[str, Any]:
    """Create an issue on GitHub via the REST API.

    Returns {"number": int, "html_url": str} on success.
    Raises on failure.
    """
    api_url = config.get("api_url", "https://api.github.com")
    owner = config["owner"]
    repo = config["repo"]
    token = config["token"]

    url = f"{api_url}/repos/{owner}/{repo}/issues"

    payload: dict[str, Any] = {
        "title": title,
        "body": body,
        "labels": labels,
    }

    assignees = config.get("assignees", [])
    if assignees:
        payload["assignees"] = assignees

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

    if response.status_code == 201:
        data = response.json()
        return {
            "number": data["number"],
            "html_url": data["html_url"],
        }
    else:
        error_msg = response.text[:300]
        raise RuntimeError(
            f"GitHub API returned {response.status_code}: {error_msg}"
        )


# ---------------------------------------------------------------------------
# Export tracking (Redis-backed)
# ---------------------------------------------------------------------------

async def record_export(
    config_id: str,
    finding_id: str,
    fingerprint: str | None,
    issue_number: int | None,
    issue_url: str | None,
    status: str,
) -> None:
    """Track an exported issue in Redis."""
    export_id = f"exp_{uuid4().hex[:12]}"
    record = {
        "id": export_id,
        "config_id": config_id,
        "finding_id": finding_id,
        "fingerprint": fingerprint,
        "github_issue_number": issue_number,
        "github_issue_url": issue_url,
        "status": status,
        "created_at": datetime.utcnow().isoformat(),
    }
    await _export_store.save(export_id, record)


async def is_already_exported(config_id: str, fingerprint: str) -> bool:
    """Check if a finding fingerprint has already been exported for this config."""
    if not fingerprint:
        return False
    exports = await _export_store.list_jobs(tenant_id=None, limit=5000)
    for exp in exports:
        if (
            exp.get("config_id") == config_id
            and exp.get("fingerprint") == fingerprint
            and exp.get("status") == "created"
        ):
            return True
    return False


async def list_exports(
    config_id: str, limit: int = 50, offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """List exported issues for a config."""
    all_exports = await _export_store.list_jobs(tenant_id=None, limit=5000)
    filtered = [e for e in all_exports if e.get("config_id") == config_id]
    total = len(filtered)
    return filtered[offset : offset + limit], total


# ---------------------------------------------------------------------------
# Batch export
# ---------------------------------------------------------------------------

async def export_findings(
    config: dict[str, Any],
    findings: list[dict[str, Any]],
    scan_id: str,
    min_severity: str = "medium",
    skip_duplicates: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Export a list of findings as GitHub Issues.

    Returns an export summary with per-finding results.
    """
    config_id = config["id"]
    severity_idx = SEVERITY_ORDER.index(min_severity) if min_severity in SEVERITY_ORDER else 2

    # Filter by severity
    filtered = []
    for f in findings:
        f_sev = (f.get("severity") or "medium").lower()
        if f_sev in SEVERITY_ORDER and SEVERITY_ORDER.index(f_sev) <= severity_idx:
            filtered.append(f)

    results: list[dict[str, Any]] = []
    exported = 0
    skipped = 0
    failed = 0

    for finding in filtered:
        finding_id = finding.get("id", "")
        fingerprint = finding.get("fingerprint")
        f_title = finding.get("title", "")
        f_severity = finding.get("severity", "medium")

        # Check duplicate
        if skip_duplicates and fingerprint and await is_already_exported(config_id, fingerprint):
            results.append({
                "finding_id": finding_id,
                "finding_title": f_title,
                "severity": f_severity,
                "github_issue_number": None,
                "github_issue_url": None,
                "status": "skipped_duplicate",
                "error": None,
            })
            skipped += 1
            continue

        title = format_issue_title(finding)
        body = format_issue_body(finding, scan_id)
        labels = build_labels(
            finding,
            config.get("labels", ["security", "mass-finding"]),
            config.get("severity_labels", True),
            config.get("category_labels", True),
        )

        if dry_run:
            results.append({
                "finding_id": finding_id,
                "finding_title": f_title,
                "severity": f_severity,
                "github_issue_number": None,
                "github_issue_url": None,
                "status": "dry_run",
                "error": None,
            })
            exported += 1
            continue

        # Create the issue on GitHub
        try:
            issue_data = await create_github_issue(config, title, body, labels)
            await record_export(
                config_id, finding_id, fingerprint,
                issue_data["number"], issue_data["html_url"], "created",
            )
            results.append({
                "finding_id": finding_id,
                "finding_title": f_title,
                "severity": f_severity,
                "github_issue_number": issue_data["number"],
                "github_issue_url": issue_data["html_url"],
                "status": "created",
                "error": None,
            })
            exported += 1
        except Exception as e:
            logger.error(
                "Failed to create GitHub issue for finding %s: %s",
                finding_id, e,
            )
            await record_export(config_id, finding_id, fingerprint, None, None, "failed")
            results.append({
                "finding_id": finding_id,
                "finding_title": f_title,
                "severity": f_severity,
                "github_issue_number": None,
                "github_issue_url": None,
                "status": "failed",
                "error": str(e)[:200],
            })
            failed += 1

    # Update config stats
    if not dry_run:
        config["total_exported"] = config.get("total_exported", 0) + exported
        config["last_export_at"] = datetime.utcnow().isoformat()
        await _config_store.save(config_id, config)

    return {
        "integration_id": config_id,
        "scan_id": scan_id,
        "total_findings": len(filtered),
        "exported": exported,
        "skipped": skipped,
        "failed": failed,
        "dry_run": dry_run,
        "issues": results,
    }
