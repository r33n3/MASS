"""SARIF format report generator.

Generates SARIF (Static Analysis Results Interchange Format) reports
compatible with GitHub Security, VS Code, and other SARIF consumers.

SARIF Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from datetime import datetime
from typing import Any

from mass.core.findings import Finding
from mass.core.types import Severity


class SarifFormatter:
    """Generates SARIF 2.1.0 format reports."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    SEVERITY_TO_LEVEL: dict[Severity, str] = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    SEVERITY_TO_RANK: dict[Severity, float] = {
        Severity.CRITICAL: 9.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 3.0,
        Severity.INFO: 1.0,
    }

    def __init__(
        self,
        tool_name: str = "MASS",
        tool_version: str = "0.1.0",
        tool_uri: str = "https://github.com/r33n3/MASS",
    ) -> None:
        """Initialize the SARIF formatter.

        Args:
            tool_name: Name of the analysis tool.
            tool_version: Version of the tool.
            tool_uri: URI to tool information.
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.tool_uri = tool_uri

    def format(
        self,
        findings: list[Finding],
        scan_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate SARIF report from findings.

        Args:
            findings: List of security findings.
            scan_id: Optional scan ID.
            metadata: Optional additional metadata.

        Returns:
            SARIF document as dictionary.
        """
        # Collect unique rules
        rules = self._generate_rules(findings)

        # Generate results
        results = self._generate_results(findings, rules)

        # Build SARIF document
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": self.tool_uri,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                }
            ],
        }

        # Add automationDetails if scan_id provided
        if scan_id:
            sarif["runs"][0]["automationDetails"] = {
                "id": scan_id,
                "guid": scan_id,
            }

        return sarif

    def _generate_rules(
        self, findings: list[Finding]
    ) -> dict[str, dict[str, Any]]:
        """Generate SARIF rules from findings.

        Returns:
            Dictionary mapping rule ID to rule definition.
        """
        rules: dict[str, dict[str, Any]] = {}

        for finding in findings:
            rule_id = f"{finding.category.value}"
            if rule_id in rules:
                continue

            rule = {
                "id": rule_id,
                "name": finding.category.value.replace("_", " ").title(),
                "shortDescription": {
                    "text": finding.category.value.replace("_", " ").title()
                },
                "fullDescription": {
                    "text": f"Security issue related to {finding.category.value}"
                },
                "defaultConfiguration": {
                    "level": self.SEVERITY_TO_LEVEL.get(finding.severity, "note")
                },
                "properties": {
                    "security-severity": str(
                        self.SEVERITY_TO_RANK.get(finding.severity, 1.0)
                    ),
                    "tags": ["security", finding.category.value],
                },
            }

            # Add help URI if available
            if finding.owasp_ids:
                rule["helpUri"] = (
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                )

            rules[rule_id] = rule

        return rules

    def _generate_results(
        self,
        findings: list[Finding],
        rules: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate SARIF results from findings."""
        results = []

        for finding in findings:
            rule_id = f"{finding.category.value}"
            rule_index = list(rules.keys()).index(rule_id)

            result: dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": self.SEVERITY_TO_LEVEL.get(finding.severity, "note"),
                "message": {
                    "text": finding.description,
                },
                "fingerprints": {
                    "primaryLocationLineHash": finding.id,
                },
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                    "component_type": finding.component_type.value,
                    "component_name": finding.component_name,
                },
            }

            # Add location if available
            if finding.file_path:
                location: dict[str, Any] = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                        }
                    }
                }
                if finding.line_number:
                    location["physicalLocation"]["region"] = {
                        "startLine": finding.line_number,
                    }
                result["locations"] = [location]

            # Add related locations from evidence
            related_locations = []
            for i, evidence in enumerate(finding.evidence):
                if evidence.source_file:
                    related_loc = {
                        "id": i,
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": evidence.source_file,
                            }
                        },
                        "message": {
                            "text": f"Evidence: {evidence.type}",
                        },
                    }
                    if evidence.source_line:
                        related_loc["physicalLocation"]["region"] = {
                            "startLine": evidence.source_line,
                        }
                    related_locations.append(related_loc)

            if related_locations:
                result["relatedLocations"] = related_locations

            # Add fixes if remediation available
            if finding.remediation:
                result["fixes"] = [
                    {
                        "description": {
                            "text": finding.remediation.summary,
                        },
                    }
                ]

            # Add compliance references
            if finding.cwe_ids or finding.owasp_ids or finding.mitre_ids:
                taxa = []
                for cwe_id in finding.cwe_ids:
                    taxa.append({
                        "id": cwe_id,
                        "toolComponent": {
                            "name": "CWE",
                        },
                    })
                for owasp_id in finding.owasp_ids:
                    taxa.append({
                        "id": owasp_id,
                        "toolComponent": {
                            "name": "OWASP-LLM",
                        },
                    })
                for mitre_id in finding.mitre_ids:
                    taxa.append({
                        "id": mitre_id,
                        "toolComponent": {
                            "name": "MITRE-ATLAS",
                        },
                    })
                result["taxa"] = taxa

            results.append(result)

        return results

    def format_to_string(
        self,
        findings: list[Finding],
        scan_id: str = "",
        pretty: bool = True,
    ) -> str:
        """Generate SARIF report as JSON string.

        Args:
            findings: List of security findings.
            scan_id: Optional scan ID.
            pretty: Whether to pretty-print JSON.

        Returns:
            SARIF JSON string.
        """
        import json

        sarif = self.format(findings, scan_id)
        if pretty:
            return json.dumps(sarif, indent=2)
        return json.dumps(sarif)
