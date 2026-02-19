"""CI/CD integration service.

Handles webhook signature verification, payload parsing for GitHub/GitLab,
scan triggering, and quality gate evaluation.
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime
from typing import Any

from mass.api.utils.job_store import JobStore
from mass.core.config import get_settings

logger = logging.getLogger(__name__)

# Redis-backed stores following Rule 1
_integration_store = JobStore("cicd_integrations", ttl=365 * 24 * 3600)  # 1 year
_build_store = JobStore("cicd_builds", ttl=30 * 24 * 3600)  # 30 days


# ---------------------------------------------------------------------------
# Webhook signature verification
# ---------------------------------------------------------------------------

def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub HMAC-SHA256 webhook signature.

    GitHub sends ``X-Hub-Signature-256: sha256=<hex>``.
    """
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(
        secret.encode(), payload, hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


def verify_gitlab_token(token: str, secret: str) -> bool:
    """Verify GitLab webhook token.

    GitLab sends ``X-Gitlab-Token: <secret>``.
    """
    return hmac.compare_digest(token, secret)


# ---------------------------------------------------------------------------
# Payload parsing — normalize provider-specific payloads
# ---------------------------------------------------------------------------

def parse_github_payload(body: dict[str, Any]) -> dict[str, Any]:
    """Extract normalized fields from a GitHub webhook payload."""
    ref = body.get("ref", "")
    branch = ref.removeprefix("refs/heads/").removeprefix("refs/tags/")

    repo = body.get("repository", {})
    repo_full_name = repo.get("full_name", "")

    head_commit = body.get("head_commit", {})
    commit_sha = head_commit.get("id") or body.get("after", "")

    # Determine event type
    if body.get("pull_request"):
        event_type = "pull_request"
        pr = body["pull_request"]
        branch = pr.get("head", {}).get("ref", branch)
        commit_sha = pr.get("head", {}).get("sha", commit_sha)
    elif ref.startswith("refs/tags/"):
        event_type = "tag"
    else:
        event_type = "push"

    return {
        "provider": "github",
        "repository": repo_full_name,
        "branch": branch,
        "commit_sha": commit_sha[:40] if commit_sha else None,
        "event_type": event_type,
        "sender": body.get("sender", {}).get("login", ""),
        "commit_message": head_commit.get("message", ""),
    }


def parse_gitlab_payload(body: dict[str, Any]) -> dict[str, Any]:
    """Extract normalized fields from a GitLab webhook payload."""
    ref = body.get("ref", "")
    branch = ref.removeprefix("refs/heads/").removeprefix("refs/tags/")

    project = body.get("project", {})
    repo_full_name = project.get("path_with_namespace", "")

    commit_sha = body.get("checkout_sha") or body.get("after", "")

    object_kind = body.get("object_kind", "push")
    if object_kind == "merge_request":
        event_type = "pull_request"
        mr = body.get("object_attributes", {})
        branch = mr.get("source_branch", branch)
        commit_sha = mr.get("last_commit", {}).get("id", commit_sha)
    elif object_kind == "tag_push":
        event_type = "tag"
    else:
        event_type = "push"

    return {
        "provider": "gitlab",
        "repository": repo_full_name,
        "branch": branch,
        "commit_sha": commit_sha[:40] if commit_sha else None,
        "event_type": event_type,
        "sender": body.get("user_username", ""),
        "commit_message": "",
    }


def parse_generic_payload(body: dict[str, Any]) -> dict[str, Any]:
    """Extract fields from a generic/custom CI webhook payload.

    Expects the caller to pass normalized fields directly.
    """
    return {
        "provider": "generic",
        "repository": body.get("repository", ""),
        "branch": body.get("branch", "main"),
        "commit_sha": body.get("commit_sha"),
        "event_type": body.get("event_type", "push"),
        "sender": body.get("sender", ""),
        "commit_message": body.get("commit_message", ""),
    }


PAYLOAD_PARSERS = {
    "github": parse_github_payload,
    "gitlab": parse_gitlab_payload,
    "generic": parse_generic_payload,
}


# ---------------------------------------------------------------------------
# Integration CRUD (Redis-backed)
# ---------------------------------------------------------------------------

async def create_integration(tenant_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Create a new CI/CD integration config."""
    from uuid import uuid4

    integration_id = f"cicd_{uuid4().hex[:12]}"
    now = datetime.utcnow().isoformat()

    record = {
        "id": integration_id,
        "tenant_id": tenant_id,
        **data,
        "total_scans": 0,
        "last_scan_at": None,
        "created_at": now,
        "updated_at": now,
    }
    await _integration_store.save(integration_id, record)
    logger.info(
        "Created CI/CD integration",
        extra={"integration_id": integration_id, "provider": data.get("provider")},
    )
    return record


async def get_integration(integration_id: str) -> dict[str, Any] | None:
    """Load an integration by ID."""
    return await _integration_store.load(integration_id)


async def list_integrations(
    tenant_id: str, limit: int = 50, offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """List integrations for a tenant. Returns (items, total)."""
    all_jobs = await _integration_store.list_jobs(tenant_id=tenant_id, limit=1000)
    total = len(all_jobs)
    return all_jobs[offset : offset + limit], total


async def update_integration(
    integration_id: str, updates: dict[str, Any],
) -> dict[str, Any] | None:
    """Update an integration's mutable fields."""
    record = await _integration_store.load(integration_id)
    if not record:
        return None
    for key, value in updates.items():
        if value is not None:
            record[key] = value
    record["updated_at"] = datetime.utcnow().isoformat()
    await _integration_store.save(integration_id, record)
    return record


async def delete_integration(integration_id: str) -> bool:
    """Delete an integration."""
    return await _integration_store.delete(integration_id)


# ---------------------------------------------------------------------------
# Webhook processing — find matching integration & trigger scan
# ---------------------------------------------------------------------------

async def find_integration_for_webhook(
    provider: str, repository: str, tenant_id: str | None = None,
) -> dict[str, Any] | None:
    """Find an active integration matching provider + repository."""
    all_integrations = await _integration_store.list_jobs(
        tenant_id=tenant_id, limit=1000,
    )
    for integ in all_integrations:
        if (
            integ.get("is_active")
            and integ.get("provider") == provider
            and integ.get("repository") == repository
        ):
            return integ
    return None


def should_trigger_scan(
    integration: dict[str, Any], parsed: dict[str, Any],
) -> bool:
    """Check if the webhook event should trigger a scan."""
    # Check event type filter
    trigger_on = integration.get("trigger_on", ["push", "pull_request"])
    if parsed["event_type"] not in trigger_on:
        return False

    # Check branch filter
    branch_filter = integration.get("branch_filter", [])
    if branch_filter and parsed["branch"] not in branch_filter:
        return False

    return True


async def create_build_record(
    integration: dict[str, Any], parsed: dict[str, Any], scan_id: str | None = None,
) -> dict[str, Any]:
    """Create a build record tracking a CI/CD-triggered scan."""
    from uuid import uuid4

    build_id = f"build_{uuid4().hex[:12]}"
    now = datetime.utcnow().isoformat()

    record = {
        "id": build_id,
        "integration_id": integration["id"],
        "scan_id": scan_id,
        "provider": parsed["provider"],
        "repository": parsed["repository"],
        "branch": parsed["branch"],
        "commit_sha": parsed.get("commit_sha"),
        "event_type": parsed["event_type"],
        "gate_verdict": "pending",
        "status": "pending" if scan_id else "skipped",
        "tenant_id": integration.get("tenant_id", "default"),
        "created_at": now,
    }
    await _build_store.save(build_id, record)

    # Increment integration scan counter
    integration["total_scans"] = integration.get("total_scans", 0) + 1
    integration["last_scan_at"] = now
    await _integration_store.save(integration["id"], integration)

    return record


async def list_builds(
    tenant_id: str, integration_id: str | None = None, limit: int = 50, offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """List build records for a tenant, optionally filtered by integration."""
    all_builds = await _build_store.list_jobs(tenant_id=tenant_id, limit=1000)
    if integration_id:
        all_builds = [b for b in all_builds if b.get("integration_id") == integration_id]
    total = len(all_builds)
    return all_builds[offset : offset + limit], total


# ---------------------------------------------------------------------------
# Gate evaluation
# ---------------------------------------------------------------------------

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


def evaluate_gate(
    severity_counts: dict[str, int],
    threshold: str,
) -> tuple[str, int, str]:
    """Evaluate whether a scan passes the CI/CD quality gate.

    Returns (verdict, findings_above_threshold, message).
    """
    threshold_idx = SEVERITY_LEVELS.index(threshold) if threshold in SEVERITY_LEVELS else 1

    findings_above = 0
    for sev in SEVERITY_LEVELS[: threshold_idx + 1]:
        findings_above += severity_counts.get(sev, 0)

    if findings_above == 0:
        return "pass", 0, f"No findings at or above {threshold} severity"
    else:
        return (
            "fail",
            findings_above,
            f"{findings_above} finding(s) at or above {threshold} severity",
        )


async def update_build_verdict(
    build_id: str, verdict: str, scan_status: str,
) -> dict[str, Any] | None:
    """Update a build record with the gate verdict."""
    record = await _build_store.load(build_id)
    if not record:
        return None
    record["gate_verdict"] = verdict
    record["status"] = scan_status
    await _build_store.save(build_id, record)
    return record
