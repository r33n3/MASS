"""Finding fingerprint computation for cross-scan identity tracking.

A fingerprint uniquely identifies a finding across scans of the same
deployment, enabling auto-closure when findings disappear and scan
comparison via diff.

The fingerprint intentionally ignores line_number (which shifts as
code changes) and description/evidence (which may vary between runs).
"""

import hashlib
import json


def compute_fingerprint(
    category: str,
    title: str,
    file_path: str | None = None,
    rule_id: str | None = None,
    component_name: str | None = None,
) -> str:
    """Compute a stable SHA-256 fingerprint for a finding.

    For file-based findings (static analysis):
        sha256(category + title + file_path + rule_id)
    For probe/dynamic findings (no file_path):
        sha256(category + title + component_name + rule_id)

    Args:
        category: Finding category (e.g. "prompt_injection").
        title: Finding title.
        file_path: Source file path, if applicable.
        rule_id: Analyzer rule ID, if applicable.
        component_name: Component name from meta, for dynamic findings.

    Returns:
        64-character hex SHA-256 digest.
    """
    # Normalize file_path separators for cross-platform stability
    normalized_path = (file_path or "").replace("\\", "/").strip()

    parts = {
        "category": (category or "").lower().strip(),
        "title": (title or "").strip(),
        "file_path": normalized_path if normalized_path else None,
        "rule_id": (rule_id or "").strip() if rule_id else None,
        "component_name": (component_name or "").strip() if not normalized_path else None,
    }

    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
