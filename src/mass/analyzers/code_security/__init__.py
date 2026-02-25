"""Code security audit analyzer.

Static grep + LLM verification for traditional AppSec vulnerabilities
(auth bypass, injection, XSS, insecure deserialization, etc.) in
application code.

Phase A (Static): Fast regex scanning across all code files to find
candidate vulnerability locations — high recall, some false positives.

Phase B (LLM Verify): Send candidates + surrounding code context to LLM
to confirm exploitability, filter false positives, and generate exploit
scenarios — high precision.
"""

from mass.analyzers.code_security.audit import AuditConfig, AuditResult, CodeSecurityAuditor
from mass.analyzers.code_security.patterns import SecurityCategory, SecurityPattern
from mass.analyzers.code_security.scanner import CodeSecurityScanner, SecurityCandidate
from mass.analyzers.code_security.verifier import CodeSecurityVerifier, VerificationResult

__all__ = [
    "AuditConfig",
    "AuditResult",
    "CodeSecurityAuditor",
    "CodeSecurityScanner",
    "CodeSecurityVerifier",
    "SecurityCandidate",
    "SecurityCategory",
    "SecurityPattern",
    "VerificationResult",
]
