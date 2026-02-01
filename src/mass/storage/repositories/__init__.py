"""Repository layer for MASS.

Provides clean data access abstractions over SQLAlchemy models.
"""

from mass.storage.repositories.base import BaseRepository
from mass.storage.repositories.tenant import TenantRepository, UserRepository, APIKeyRepository
from mass.storage.repositories.deployment import DeploymentRepository, ComponentRepository
from mass.storage.repositories.scan import ScanRepository, ScanJobRepository
from mass.storage.repositories.finding import FindingRepository, EvidenceRepository
from mass.storage.repositories.report import ReportRepository

__all__ = [
    "BaseRepository",
    "TenantRepository",
    "UserRepository",
    "APIKeyRepository",
    "DeploymentRepository",
    "ComponentRepository",
    "ScanRepository",
    "ScanJobRepository",
    "FindingRepository",
    "EvidenceRepository",
    "ReportRepository",
]
