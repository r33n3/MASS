"""Add finding fingerprint and closure tracking columns.

Revision ID: c5d6e7f8a9b0
Revises: b4e5f6a7b8c9
Create Date: 2026-02-06 10:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c5d6e7f8a9b0"
down_revision: Union[str, None] = "b4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("fingerprint", sa.String(64), nullable=True))
    op.add_column(
        "findings",
        sa.Column(
            "closed_by_scan_id",
            sa.String(36),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index(
        "ix_findings_scan_fingerprint",
        "findings",
        ["scan_id", "fingerprint"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_findings_scan_fingerprint", table_name="findings")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_column("findings", "closed_by_scan_id")
    op.drop_column("findings", "fingerprint")
