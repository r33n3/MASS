"""Confidence calibration engine.

Tracks triage outcomes (user marking findings as confirmed/false_positive)
and adjusts confidence scores for future findings based on historical
accuracy per analyzer × category.

This is a lightweight scoring adjustment — no retraining involved.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CalibrationStats:
    """Statistics for a single analyzer/category combination."""

    total_findings: int = 0
    confirmed: int = 0
    false_positives: int = 0
    disputed: int = 0

    @property
    def false_positive_rate(self) -> float:
        """Calculate false positive rate."""
        if self.total_findings == 0:
            return 0.0
        return self.false_positives / self.total_findings

    @property
    def precision(self) -> float:
        """Calculate precision (confirmed / (confirmed + false_positives))."""
        denom = self.confirmed + self.false_positives
        if denom == 0:
            return 1.0  # No data = assume perfect
        return self.confirmed / denom

    @property
    def confidence_adjustment(self) -> float:
        """Calculate confidence adjustment factor.

        Returns a multiplier (0.0 to 1.0) based on historical precision.
        - Precision 1.0 → adjustment 1.0 (no change)
        - Precision 0.5 → adjustment 0.5 (halve confidence)
        - Precision 0.0 → adjustment 0.1 (minimum floor)
        """
        return max(0.1, self.precision)


@dataclass
class CalibrationProfile:
    """Complete calibration profile across all analyzer/category combos."""

    stats: dict[str, CalibrationStats] = field(default_factory=dict)
    last_updated: str = ""

    def get_adjustment(self, analyzer: str, category: str) -> float:
        """Get confidence adjustment for an analyzer/category pair.

        Args:
            analyzer: Analyzer name (e.g., "context_analyzer").
            category: Finding category (e.g., "prompt_injection").

        Returns:
            Confidence multiplier (0.1 to 1.0).
        """
        # Try specific key first
        key = f"{analyzer}:{category}"
        if key in self.stats and self.stats[key].total_findings >= 5:
            return self.stats[key].confidence_adjustment

        # Fall back to analyzer-level stats
        analyzer_key = f"{analyzer}:*"
        if analyzer_key in self.stats and self.stats[analyzer_key].total_findings >= 5:
            return self.stats[analyzer_key].confidence_adjustment

        # No data = no adjustment
        return 1.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "last_updated": self.last_updated,
            "stats": {
                k: {
                    "total_findings": v.total_findings,
                    "confirmed": v.confirmed,
                    "false_positives": v.false_positives,
                    "disputed": v.disputed,
                    "precision": round(v.precision, 3),
                    "confidence_adjustment": round(v.confidence_adjustment, 3),
                }
                for k, v in self.stats.items()
            },
        }


class CalibrationEngine:
    """Computes and applies confidence calibration from triage history.

    Usage:
        engine = CalibrationEngine()
        profile = await engine.compute_profile(finding_repo, tenant_id)
        adjusted = engine.adjust_confidence(profile, finding)
    """

    async def compute_profile(
        self,
        finding_repo: Any,
        tenant_id: str | None = None,
    ) -> CalibrationProfile:
        """Compute calibration profile from historical triage data.

        Queries all findings with a non-null status (confirmed, false_positive,
        disputed) and computes precision per analyzer × category.

        Args:
            finding_repo: FindingRepository instance.
            tenant_id: Optional tenant filter.

        Returns:
            CalibrationProfile with per-analyzer stats.
        """
        from datetime import datetime

        profile = CalibrationProfile(last_updated=datetime.utcnow().isoformat())

        # Query triaged findings
        try:
            triaged = await finding_repo.list_triaged(tenant_id=tenant_id)
        except Exception as e:
            logger.warning("Failed to query triaged findings: %s", e)
            return profile

        for finding in triaged:
            triage_status = getattr(finding, "status", None)
            if not triage_status or triage_status == "open":
                continue

            # Determine analyzer from metadata or tags
            meta = {}
            if finding.meta:
                import json
                try:
                    meta = json.loads(finding.meta)
                except (ValueError, TypeError):
                    pass

            analyzer = meta.get("analyzer", "unknown")
            category = finding.category or "unknown"

            # Update specific key
            key = f"{analyzer}:{category}"
            if key not in profile.stats:
                profile.stats[key] = CalibrationStats()

            stats = profile.stats[key]
            stats.total_findings += 1

            if triage_status in ("confirmed", "true_positive"):
                stats.confirmed += 1
            elif triage_status in ("false_positive", "suppressed"):
                stats.false_positives += 1
            elif triage_status == "disputed":
                stats.disputed += 1

            # Also update analyzer-level aggregate
            agg_key = f"{analyzer}:*"
            if agg_key not in profile.stats:
                profile.stats[agg_key] = CalibrationStats()

            agg = profile.stats[agg_key]
            agg.total_findings += 1
            if triage_status in ("confirmed", "true_positive"):
                agg.confirmed += 1
            elif triage_status in ("false_positive", "suppressed"):
                agg.false_positives += 1
            elif triage_status == "disputed":
                agg.disputed += 1

        logger.info(
            "Calibration profile computed: %d analyzer/category combos, %d total triaged",
            len(profile.stats),
            sum(s.total_findings for s in profile.stats.values()) // 2,  # /2 because of aggregates
        )

        return profile

    def adjust_confidence(
        self,
        profile: CalibrationProfile,
        finding: Any,
    ) -> float:
        """Adjust a finding's confidence based on calibration profile.

        Args:
            profile: Calibration profile.
            finding: Finding to adjust.

        Returns:
            Adjusted confidence score (0.0 to 1.0).
        """
        meta = {}
        if hasattr(finding, "meta") and finding.meta:
            import json
            try:
                meta = json.loads(finding.meta)
            except (ValueError, TypeError):
                pass

        analyzer = meta.get("analyzer", "unknown")
        category = getattr(finding, "category", "unknown") or "unknown"
        original_confidence = getattr(finding, "confidence", 0.5) or 0.5

        adjustment = profile.get_adjustment(analyzer, category)
        adjusted = original_confidence * adjustment

        return round(min(1.0, max(0.0, adjusted)), 3)

    def adjust_findings(
        self,
        profile: CalibrationProfile,
        findings: list[Any],
    ) -> list[tuple[Any, float]]:
        """Adjust confidence for a batch of findings.

        Args:
            profile: Calibration profile.
            findings: Findings to adjust.

        Returns:
            List of (finding, adjusted_confidence) tuples.
        """
        return [
            (f, self.adjust_confidence(profile, f))
            for f in findings
        ]
