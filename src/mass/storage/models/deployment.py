"""Deployment and scan models."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from mass.storage.models.base import Base, TimestampMixin, UUIDMixin


class DeploymentType(str, enum.Enum):
    """Deployment type enumeration."""

    AGENT = "agent"
    CHATBOT = "chatbot"
    API = "api"
    WORKFLOW = "workflow"
    OTHER = "other"


class Deployment(Base, UUIDMixin, TimestampMixin):
    """Deployment model."""

    __tablename__ = "deployments"

    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deployment_type: Mapped[str] = mapped_column(
        String(50),
        default=DeploymentType.OTHER.value,
        nullable=False,
    )

    # Source information
    source_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    source_branch: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_commit: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Scheduling (cron expression, e.g. "0 2 * * 1" = Monday 2AM)
    scan_schedule: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    scan_schedule_profile: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True, default="standard"
    )

    # Metadata (renamed to avoid SQLAlchemy reserved name)
    meta: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    scans: Mapped[list["Scan"]] = relationship(back_populates="deployment", cascade="all, delete-orphan")


class ScanStatus(str, enum.Enum):
    """Scan status enumeration."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(str, enum.Enum):
    """Scan profile enumeration."""

    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"


class Scan(Base, UUIDMixin, TimestampMixin):
    """Scan model."""

    __tablename__ = "scans"

    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    deployment_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("deployments.id", ondelete="CASCADE"),
        nullable=False,
    )

    profile: Mapped[str] = mapped_column(
        String(50),
        default=ScanProfile.STANDARD.value,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=ScanStatus.PENDING.value,
        nullable=False,
    )

    # Progress tracking
    progress_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    current_phase: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    jobs_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    jobs_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Results summary
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Error information
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Configuration
    config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Final verdict (JSON from FinalJudge)
    verdict: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # AI threat model (JSON from ThreatModelBuilder)
    threat_model: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    deployment: Mapped["Deployment"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        foreign_keys="[Finding.scan_id]",
    )
    reports: Mapped[list["Report"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
