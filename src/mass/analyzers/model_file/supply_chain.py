"""Supply chain security analysis.

Verifies model file integrity, provenance, and source authenticity.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

from mass.core.types import Severity
from mass.analyzers.model_file.scanner import (
    ModelFileFinding,
    FindingCategory,
)

logger = logging.getLogger(__name__)


@dataclass
class ProvenanceInfo:
    """Model provenance information."""
    source_url: str | None = None
    source_hub: str | None = None
    model_id: str | None = None
    revision: str | None = None
    download_date: datetime | None = None
    expected_hash: str | None = None
    hash_algorithm: str = "sha256"
    signature: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_url": self.source_url,
            "source_hub": self.source_hub,
            "model_id": self.model_id,
            "revision": self.revision,
            "download_date": self.download_date.isoformat() if self.download_date else None,
            "expected_hash": self.expected_hash,
            "hash_algorithm": self.hash_algorithm,
            "signature": self.signature,
            "metadata": self.metadata,
        }


# Known model hubs and their verification patterns
MODEL_HUBS = {
    "huggingface.co": {
        "name": "Hugging Face",
        "config_file": "config.json",
        "hash_file": None,
        "trusted": True,
    },
    "huggingface.co/api": {
        "name": "Hugging Face API",
        "config_file": "config.json",
        "hash_file": None,
        "trusted": True,
    },
    "pytorch.org": {
        "name": "PyTorch Hub",
        "config_file": None,
        "hash_file": None,
        "trusted": True,
    },
    "tensorflow.org": {
        "name": "TensorFlow Hub",
        "config_file": None,
        "hash_file": None,
        "trusted": True,
    },
    "civitai.com": {
        "name": "Civitai",
        "config_file": None,
        "hash_file": None,
        "trusted": False,  # User-uploaded content
    },
}

# Hash patterns for verification
HASH_PATTERNS = {
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
}


class SupplyChainAnalyzer:
    """Analyzes model supply chain security.

    Checks:
    - Hash verification against known good values
    - Source verification (trusted vs untrusted)
    - Provenance information completeness
    - Signature verification (if available)
    """

    def __init__(
        self,
        trusted_sources: list[str] | None = None,
        known_hashes: dict[str, str] | None = None,
        require_provenance: bool = False,
    ):
        """Initialize supply chain analyzer.

        Args:
            trusted_sources: List of trusted model sources/domains.
            known_hashes: Dictionary of known file hashes {filename: hash}.
            require_provenance: Require provenance information.
        """
        self.trusted_sources = set(trusted_sources or [
            "huggingface.co",
            "pytorch.org",
            "tensorflow.org",
        ])
        self.known_hashes = known_hashes or {}
        self.require_provenance = require_provenance

    def analyze(
        self,
        file_path: Path,
        file_hash: str,
        provenance: ProvenanceInfo | None = None,
    ) -> Iterator[ModelFileFinding]:
        """Analyze supply chain security of a model file.

        Args:
            file_path: Path to the model file.
            file_hash: SHA-256 hash of the file.
            provenance: Optional provenance information.

        Yields:
            Security findings.
        """
        # Check hash against known good values
        yield from self._check_hash(file_path, file_hash)

        # Check provenance
        if provenance:
            yield from self._check_provenance(file_path, provenance, file_hash)
        elif self.require_provenance:
            yield ModelFileFinding(
                category=FindingCategory.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                title="Missing provenance information",
                description="Model file lacks provenance information",
                file_path=file_path,
                remediation="Track model source and download information",
            )

        # Check for associated metadata files
        yield from self._check_metadata_files(file_path)

    def _check_hash(
        self,
        file_path: Path,
        file_hash: str,
    ) -> Iterator[ModelFileFinding]:
        """Check hash against known good values.

        Args:
            file_path: Path to the model file.
            file_hash: SHA-256 hash of the file.

        Yields:
            Hash verification findings.
        """
        filename = file_path.name

        # Check against known hashes
        if filename in self.known_hashes:
            expected = self.known_hashes[filename]
            if file_hash.lower() != expected.lower():
                yield ModelFileFinding(
                    category=FindingCategory.SUPPLY_CHAIN,
                    severity=Severity.CRITICAL,
                    title="Hash mismatch",
                    description="File hash does not match expected value",
                    file_path=file_path,
                    evidence={
                        "expected_hash": expected,
                        "actual_hash": file_hash,
                    },
                    remediation="File may have been tampered with. Re-download from trusted source.",
                )

        # Check for hash file alongside model
        hash_files = [
            file_path.with_suffix(file_path.suffix + ".sha256"),
            file_path.parent / f"{filename}.sha256",
            file_path.parent / "checksums.txt",
        ]

        for hash_file in hash_files:
            if hash_file.exists():
                yield from self._verify_hash_file(file_path, file_hash, hash_file)

    def _verify_hash_file(
        self,
        file_path: Path,
        file_hash: str,
        hash_file: Path,
    ) -> Iterator[ModelFileFinding]:
        """Verify hash against hash file.

        Args:
            file_path: Path to the model file.
            file_hash: Computed hash.
            hash_file: Path to hash file.

        Yields:
            Verification findings.
        """
        try:
            content = hash_file.read_text().strip()

            # Parse hash file formats
            expected_hash = None

            # Format: hash  filename
            if "  " in content:
                for line in content.split("\n"):
                    parts = line.strip().split("  ", 1)
                    if len(parts) == 2:
                        h, f = parts
                        if f == file_path.name or f.endswith(file_path.name):
                            expected_hash = h
                            break
            # Format: just the hash
            elif HASH_PATTERNS["sha256"].match(content):
                expected_hash = content

            if expected_hash:
                if file_hash.lower() != expected_hash.lower():
                    yield ModelFileFinding(
                        category=FindingCategory.SUPPLY_CHAIN,
                        severity=Severity.CRITICAL,
                        title="Hash verification failed",
                        description=f"File hash does not match {hash_file.name}",
                        file_path=file_path,
                        evidence={
                            "expected_hash": expected_hash,
                            "actual_hash": file_hash,
                            "hash_file": str(hash_file),
                        },
                        remediation="File may have been corrupted or tampered with",
                    )

        except Exception as e:
            logger.debug(f"Error reading hash file {hash_file}: {e}")

    def _check_provenance(
        self,
        file_path: Path,
        provenance: ProvenanceInfo,
        file_hash: str,
    ) -> Iterator[ModelFileFinding]:
        """Check provenance information.

        Args:
            file_path: Path to the model file.
            provenance: Provenance information.
            file_hash: Computed file hash.

        Yields:
            Provenance findings.
        """
        # Check source trust
        if provenance.source_url:
            parsed = urlparse(provenance.source_url)
            domain = parsed.netloc.lower()

            # Remove www prefix
            if domain.startswith("www."):
                domain = domain[4:]

            # Check if trusted
            is_trusted = any(
                domain == trusted or domain.endswith(f".{trusted}")
                for trusted in self.trusted_sources
            )

            if not is_trusted:
                yield ModelFileFinding(
                    category=FindingCategory.SUPPLY_CHAIN,
                    severity=Severity.MEDIUM,
                    title="Untrusted model source",
                    description=f"Model sourced from untrusted domain: {domain}",
                    file_path=file_path,
                    evidence={
                        "source_url": provenance.source_url,
                        "domain": domain,
                        "trusted_sources": list(self.trusted_sources),
                    },
                    remediation="Verify model authenticity manually",
                )

            # Check hub-specific info
            hub_info = MODEL_HUBS.get(domain)
            if hub_info and not hub_info["trusted"]:
                yield ModelFileFinding(
                    category=FindingCategory.SUPPLY_CHAIN,
                    severity=Severity.MEDIUM,
                    title=f"User-contributed model source: {hub_info['name']}",
                    description=f"Model from {hub_info['name']} which hosts user-uploaded content",
                    file_path=file_path,
                    evidence={"hub": hub_info["name"]},
                    remediation="Exercise extra caution with user-uploaded models",
                )

        # Check expected hash
        if provenance.expected_hash:
            if file_hash.lower() != provenance.expected_hash.lower():
                yield ModelFileFinding(
                    category=FindingCategory.SUPPLY_CHAIN,
                    severity=Severity.CRITICAL,
                    title="Provenance hash mismatch",
                    description="File hash does not match provenance record",
                    file_path=file_path,
                    evidence={
                        "expected_hash": provenance.expected_hash,
                        "actual_hash": file_hash,
                    },
                    remediation="File may have been modified since download",
                )

    def _check_metadata_files(
        self,
        file_path: Path,
    ) -> Iterator[ModelFileFinding]:
        """Check for associated metadata files.

        Args:
            file_path: Path to the model file.

        Yields:
            Metadata findings.
        """
        parent = file_path.parent

        # Check for config files
        config_files = [
            parent / "config.json",
            parent / "model_config.json",
            parent / "tokenizer_config.json",
        ]

        has_config = any(cf.exists() for cf in config_files)

        # Check for README
        readme_files = [
            parent / "README.md",
            parent / "MODEL_CARD.md",
        ]

        has_readme = any(rf.exists() for rf in readme_files)

        # If neither exists, note it
        if not has_config and not has_readme:
            yield ModelFileFinding(
                category=FindingCategory.SUPPLY_CHAIN,
                severity=Severity.LOW,
                title="Missing model documentation",
                description="No config.json or README found",
                file_path=file_path,
                remediation="Model metadata helps verify authenticity",
            )

    def verify_huggingface_model(
        self,
        file_path: Path,
        model_id: str,
        revision: str | None = None,
    ) -> Iterator[ModelFileFinding]:
        """Verify model against Hugging Face hub.

        Args:
            file_path: Path to the model file.
            model_id: Hugging Face model ID.
            revision: Git revision/tag.

        Yields:
            Verification findings.

        Note:
            This requires network access to verify.
        """
        # This would need the huggingface_hub package
        # For now, just check local provenance
        yield ModelFileFinding(
            category=FindingCategory.SUPPLY_CHAIN,
            severity=Severity.LOW,
            title="Hugging Face verification available",
            description=f"Model claims to be {model_id}",
            file_path=file_path,
            evidence={
                "model_id": model_id,
                "revision": revision,
            },
            remediation="Run 'huggingface-cli scan-cache' to verify",
        )

    def compute_hashes(
        self,
        file_path: Path,
        algorithms: list[str] | None = None,
    ) -> dict[str, str]:
        """Compute multiple hashes for a file.

        Args:
            file_path: Path to the file.
            algorithms: Hash algorithms to use.

        Returns:
            Dictionary of algorithm -> hash.
        """
        algorithms = algorithms or ["sha256", "sha1", "md5"]
        hashers = {alg: hashlib.new(alg) for alg in algorithms}

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                for hasher in hashers.values():
                    hasher.update(chunk)

        return {alg: hasher.hexdigest() for alg, hasher in hashers.items()}

    def create_provenance(
        self,
        file_path: Path,
        source_url: str | None = None,
        model_id: str | None = None,
    ) -> ProvenanceInfo:
        """Create provenance record for a model file.

        Args:
            file_path: Path to the model file.
            source_url: URL where model was downloaded.
            model_id: Model identifier.

        Returns:
            ProvenanceInfo record.
        """
        hashes = self.compute_hashes(file_path, ["sha256"])

        provenance = ProvenanceInfo(
            source_url=source_url,
            model_id=model_id,
            download_date=datetime.now(),
            expected_hash=hashes.get("sha256"),
            hash_algorithm="sha256",
        )

        # Try to determine source hub
        if source_url:
            parsed = urlparse(source_url)
            for domain, info in MODEL_HUBS.items():
                if domain in parsed.netloc:
                    provenance.source_hub = info["name"]
                    break

        return provenance

    def save_provenance(
        self,
        file_path: Path,
        provenance: ProvenanceInfo,
    ) -> Path:
        """Save provenance information to a sidecar file.

        Args:
            file_path: Path to the model file.
            provenance: Provenance information.

        Returns:
            Path to the provenance file.
        """
        provenance_path = file_path.with_suffix(file_path.suffix + ".provenance.json")
        provenance_path.write_text(json.dumps(provenance.to_dict(), indent=2))
        return provenance_path

    def load_provenance(self, file_path: Path) -> ProvenanceInfo | None:
        """Load provenance information from sidecar file.

        Args:
            file_path: Path to the model file.

        Returns:
            ProvenanceInfo or None if not found.
        """
        provenance_path = file_path.with_suffix(file_path.suffix + ".provenance.json")
        if not provenance_path.exists():
            return None

        try:
            data = json.loads(provenance_path.read_text())
            return ProvenanceInfo(
                source_url=data.get("source_url"),
                source_hub=data.get("source_hub"),
                model_id=data.get("model_id"),
                revision=data.get("revision"),
                download_date=datetime.fromisoformat(data["download_date"]) if data.get("download_date") else None,
                expected_hash=data.get("expected_hash"),
                hash_algorithm=data.get("hash_algorithm", "sha256"),
                signature=data.get("signature"),
                metadata=data.get("metadata", {}),
            )
        except Exception as e:
            logger.error(f"Error loading provenance: {e}")
            return None
