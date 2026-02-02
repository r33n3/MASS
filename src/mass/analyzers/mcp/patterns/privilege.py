"""Privilege escalation patterns.

Patterns for detecting privilege escalation attempts via MCP tools.
"""

from dataclasses import dataclass
from mass.core.types import Severity


@dataclass
class PrivilegePattern:
    """Pattern for detecting privilege escalation."""
    name: str
    pattern: str
    severity: Severity
    description: str
    privilege_type: str  # system, file, network, tool


# Privilege escalation patterns
PRIVILEGE_PATTERNS = [
    # System privilege escalation
    PrivilegePattern(
        name="sudo_request",
        pattern=r"(sudo|su\s+-|as\s+root|with\s+root|elevated)",
        severity=Severity.CRITICAL,
        description="Requests root/admin privileges",
        privilege_type="system",
    ),
    PrivilegePattern(
        name="admin_access",
        pattern=r"(admin|administrator|superuser)\s*(access|privileges?|permissions?|mode)",
        severity=Severity.HIGH,
        description="Requests administrator access",
        privilege_type="system",
    ),
    PrivilegePattern(
        name="permission_change",
        pattern=r"(change|modify|set)\s*(permissions?|access\s*rights?|ownership)",
        severity=Severity.HIGH,
        description="Modifies system permissions",
        privilege_type="system",
    ),

    # File system privilege escalation
    PrivilegePattern(
        name="root_access",
        pattern=r"(access|read|write)\s*/\s*(etc|root|sys|proc)",
        severity=Severity.HIGH,
        description="Accesses sensitive system directories",
        privilege_type="file",
    ),
    PrivilegePattern(
        name="home_access",
        pattern=r"(access|read)\s*(~|/home|user)\s*(directory|folder|files?)",
        severity=Severity.MEDIUM,
        description="Accesses user home directories",
        privilege_type="file",
    ),
    PrivilegePattern(
        name="ssh_access",
        pattern=r"(\.ssh|ssh\s+keys?|authorized_keys)",
        severity=Severity.CRITICAL,
        description="Accesses SSH keys/configuration",
        privilege_type="file",
    ),

    # Network privilege escalation
    PrivilegePattern(
        name="bind_privileged_port",
        pattern=r"(bind|listen)\s*(port\s*)?(80|443|22|21|25|53)",
        severity=Severity.HIGH,
        description="Binds to privileged network ports",
        privilege_type="network",
    ),
    PrivilegePattern(
        name="raw_socket",
        pattern=r"(raw|packet)\s*(socket|capture|sniff)",
        severity=Severity.HIGH,
        description="Uses raw sockets for packet capture",
        privilege_type="network",
    ),
    PrivilegePattern(
        name="firewall_modify",
        pattern=r"(modify|change|add|delete)\s*(firewall|iptables|ufw)\s*(rules?)?",
        severity=Severity.CRITICAL,
        description="Modifies firewall rules",
        privilege_type="network",
    ),

    # Tool/capability privilege escalation
    PrivilegePattern(
        name="grant_permissions",
        pattern=r"(grant|give|allow)\s*(all|full|unlimited)\s*(access|permissions?|privileges?)",
        severity=Severity.HIGH,
        description="Grants excessive permissions",
        privilege_type="tool",
    ),
    PrivilegePattern(
        name="auto_approve",
        pattern=r"(auto|automatic)\s*(approve|grant|allow)",
        severity=Severity.MEDIUM,
        description="Requests automatic approval of actions",
        privilege_type="tool",
    ),
    PrivilegePattern(
        name="bypass_confirmation",
        pattern=r"(bypass|skip|disable)\s*(confirmation|approval|consent)",
        severity=Severity.HIGH,
        description="Bypasses user confirmation",
        privilege_type="tool",
    ),
    PrivilegePattern(
        name="no_restrictions",
        pattern=r"(no|without|remove|disable)\s*(restrictions?|limits?|constraints?)",
        severity=Severity.HIGH,
        description="Removes security restrictions",
        privilege_type="tool",
    ),

    # Credential escalation
    PrivilegePattern(
        name="credential_steal",
        pattern=r"(capture|steal|harvest|extract)\s*(credentials?|passwords?|tokens?)",
        severity=Severity.CRITICAL,
        description="Steals credentials",
        privilege_type="system",
    ),
    PrivilegePattern(
        name="keylogger",
        pattern=r"(keylog|keystroke|input)\s*(capture|record|log)",
        severity=Severity.CRITICAL,
        description="Captures keystrokes",
        privilege_type="system",
    ),
]
