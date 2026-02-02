"""Privilege escalation attack patterns.

Detects patterns that enable privilege escalation in AI systems.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from mass.core.types import Severity


@dataclass
class PrivilegeEscalationPattern:
    """Pattern for detecting privilege escalation vulnerabilities."""
    name: str
    pattern: str | None
    severity: Severity
    description: str
    check_type: str  # config, permission, action


# Privilege escalation patterns
PRIVILEGE_ESCALATION_PATTERNS = [
    PrivilegeEscalationPattern(
        name="admin_role_request",
        pattern=r"(make\s+me|grant\s+me|give\s+me)\s+(admin|root|superuser)",
        severity=Severity.HIGH,
        description="Attempt to request admin privileges",
        check_type="action",
    ),
    PrivilegeEscalationPattern(
        name="sudo_command",
        pattern=r"(sudo|su\s+-|as\s+root|runas\s+/user)",
        severity=Severity.CRITICAL,
        description="Attempt to execute privileged commands",
        check_type="action",
    ),
    PrivilegeEscalationPattern(
        name="permission_modification",
        pattern=r"(chmod|chown|setfacl|icacls)\s+.*(777|\+x|everyone)",
        severity=Severity.HIGH,
        description="Attempt to modify file permissions",
        check_type="action",
    ),
    PrivilegeEscalationPattern(
        name="env_manipulation",
        pattern=r"(export|set)\s+(PATH|LD_PRELOAD|PYTHONPATH)=",
        severity=Severity.MEDIUM,
        description="Attempt to manipulate environment variables",
        check_type="action",
    ),
    PrivilegeEscalationPattern(
        name="no_role_restriction",
        pattern=r"(role_check|enforce_roles?)\s*[=:]\s*(false|disabled|none)",
        severity=Severity.HIGH,
        description="Role-based access control is disabled",
        check_type="config",
    ),
    PrivilegeEscalationPattern(
        name="wildcard_permission",
        pattern=r"(permissions?|access)\s*[=:]\s*\[?\s*['\"]?\*['\"]?\s*\]?",
        severity=Severity.CRITICAL,
        description="Wildcard permissions granted",
        check_type="config",
    ),
    PrivilegeEscalationPattern(
        name="auto_elevate",
        pattern=r"(auto_elevate|auto_approve_admin)\s*[=:]\s*true",
        severity=Severity.HIGH,
        description="Automatic privilege elevation enabled",
        check_type="config",
    ),
    PrivilegeEscalationPattern(
        name="bypass_approval",
        pattern=r"(skip_approval|bypass_auth)\s*[=:]\s*true",
        severity=Severity.CRITICAL,
        description="Approval workflow can be bypassed",
        check_type="config",
    ),
    PrivilegeEscalationPattern(
        name="credential_access",
        pattern=r"(read|access|get)\s*(credential|password|secret|api[_\s]?key)",
        severity=Severity.HIGH,
        description="Attempt to access credentials",
        check_type="action",
    ),
    PrivilegeEscalationPattern(
        name="service_account",
        pattern=r"(use|assume|impersonate)\s+(service|system)\s*account",
        severity=Severity.HIGH,
        description="Attempt to use service account",
        check_type="action",
    ),
]


@dataclass
class PrivilegeEscalationFinding:
    """A privilege escalation vulnerability finding."""
    pattern_name: str
    severity: Severity
    description: str
    evidence: str
    location: str
    affected_permissions: list[str] = field(default_factory=list)
    remediation: str = ""


class PrivilegeEscalationDetector:
    """Detects privilege escalation vulnerabilities.

    Analyzes:
    - Actions for escalation attempts
    - Configurations for weak access controls
    - Permission assignments for over-provisioning
    """

    def __init__(
        self,
        custom_patterns: list[PrivilegeEscalationPattern] | None = None,
    ):
        """Initialize detector.

        Args:
            custom_patterns: Additional patterns to use.
        """
        self.patterns = PRIVILEGE_ESCALATION_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def analyze_action(
        self,
        content: str,
        source: str = "action",
    ) -> Iterator[PrivilegeEscalationFinding]:
        """Analyze action content for escalation attempts.

        Args:
            content: Action content to analyze.
            source: Source identifier.

        Yields:
            PrivilegeEscalationFinding for each detection.
        """
        for pattern in self.patterns:
            if pattern.check_type != "action" or not pattern.pattern:
                continue

            regex = re.compile(pattern.pattern, re.IGNORECASE)
            for match in regex.finditer(content):
                yield PrivilegeEscalationFinding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    evidence=match.group(0)[:200],
                    location=source,
                    remediation=self._get_remediation(pattern.name),
                )

    def analyze_config(
        self,
        config: dict[str, Any] | str,
    ) -> Iterator[PrivilegeEscalationFinding]:
        """Analyze configuration for escalation vulnerabilities.

        Args:
            config: Configuration dict or string.

        Yields:
            PrivilegeEscalationFinding for each issue.
        """
        if isinstance(config, dict):
            config_str = str(config)
        else:
            config_str = config

        for pattern in self.patterns:
            if pattern.check_type != "config" or not pattern.pattern:
                continue

            regex = re.compile(pattern.pattern, re.IGNORECASE)
            for match in regex.finditer(config_str):
                yield PrivilegeEscalationFinding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    evidence=match.group(0)[:200],
                    location="configuration",
                    remediation=self._get_remediation(pattern.name),
                )

        # Check for specific config issues
        if isinstance(config, dict):
            yield from self._check_config_permissions(config)

    def analyze_permissions(
        self,
        permissions: list[str] | dict[str, list[str]],
    ) -> Iterator[PrivilegeEscalationFinding]:
        """Analyze permission assignments.

        Args:
            permissions: List of permissions or role->permissions mapping.

        Yields:
            PrivilegeEscalationFinding for issues.
        """
        # Flatten permissions if dict
        if isinstance(permissions, dict):
            all_perms = []
            for role, perms in permissions.items():
                all_perms.extend(perms)
        else:
            all_perms = permissions

        # Check for dangerous permissions
        dangerous_perms = {
            "admin": Severity.HIGH,
            "root": Severity.CRITICAL,
            "execute_any": Severity.CRITICAL,
            "modify_system": Severity.HIGH,
            "access_all": Severity.HIGH,
            "delete_any": Severity.HIGH,
            "*": Severity.CRITICAL,
        }

        for perm in all_perms:
            perm_lower = perm.lower()
            for dangerous, severity in dangerous_perms.items():
                if dangerous in perm_lower or perm_lower == "*":
                    yield PrivilegeEscalationFinding(
                        pattern_name="dangerous_permission",
                        severity=severity,
                        description=f"Dangerous permission assigned: {perm}",
                        evidence=perm,
                        location="permissions",
                        affected_permissions=[perm],
                        remediation="Apply principle of least privilege",
                    )
                    break

        # Check for permission scope
        if len(all_perms) > 20:
            yield PrivilegeEscalationFinding(
                pattern_name="excessive_permissions",
                severity=Severity.MEDIUM,
                description=f"Excessive permissions assigned: {len(all_perms)}",
                evidence=f"{len(all_perms)} permissions",
                location="permissions",
                affected_permissions=all_perms[:10],
                remediation="Review and reduce permission count",
            )

    def _check_config_permissions(
        self,
        config: dict[str, Any],
    ) -> Iterator[PrivilegeEscalationFinding]:
        """Check configuration for permission issues.

        Args:
            config: Configuration dict.

        Yields:
            Findings for issues.
        """
        # Check if role enforcement is disabled
        if not config.get("enforce_roles", True):
            yield PrivilegeEscalationFinding(
                pattern_name="roles_not_enforced",
                severity=Severity.HIGH,
                description="Role enforcement is disabled",
                evidence="enforce_roles: false",
                location="configuration",
                remediation="Enable role enforcement",
            )

        # Check for missing approval workflows
        sensitive_actions = config.get("sensitive_actions", [])
        approval_required = config.get("require_approval", [])

        unapproved_sensitive = set(sensitive_actions) - set(approval_required)
        if unapproved_sensitive:
            yield PrivilegeEscalationFinding(
                pattern_name="unapproved_sensitive_actions",
                severity=Severity.MEDIUM,
                description="Sensitive actions don't require approval",
                evidence=str(list(unapproved_sensitive)[:5]),
                location="configuration",
                affected_permissions=list(unapproved_sensitive),
                remediation="Add approval workflow for sensitive actions",
            )

        # Check for default permissions
        if config.get("default_permissions") == ["*"]:
            yield PrivilegeEscalationFinding(
                pattern_name="default_wildcard",
                severity=Severity.CRITICAL,
                description="Default permissions include wildcard",
                evidence="default_permissions: ['*']",
                location="configuration",
                remediation="Remove wildcard from default permissions",
            )

    def _get_remediation(self, pattern_name: str) -> str:
        """Get remediation suggestion for a pattern.

        Args:
            pattern_name: Name of the pattern.

        Returns:
            Remediation suggestion.
        """
        remediations = {
            "admin_role_request": "Block admin role requests; require separate auth",
            "sudo_command": "Disable privileged command execution",
            "permission_modification": "Restrict file permission changes",
            "env_manipulation": "Sandbox environment variable access",
            "no_role_restriction": "Enable role-based access control",
            "wildcard_permission": "Replace wildcards with explicit permissions",
            "auto_elevate": "Disable automatic privilege elevation",
            "bypass_approval": "Remove approval bypass capability",
            "credential_access": "Restrict credential access to secure storage",
            "service_account": "Restrict service account impersonation",
            "dangerous_permission": "Apply principle of least privilege",
            "excessive_permissions": "Audit and reduce permission count",
            "roles_not_enforced": "Enable strict role enforcement",
            "unapproved_sensitive_actions": "Require approval for sensitive actions",
            "default_wildcard": "Set minimal default permissions",
        }

        return remediations.get(pattern_name, "Review access control configuration")
