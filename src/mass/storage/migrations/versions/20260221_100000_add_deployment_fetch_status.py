"""Add fetch_status column to deployments for remote target tracking.

Supports host-import, S3, Azure Blob, GCS, and HTTP archive target sources
that require background downloading before scanning.

Revision ID: b2c3d4e5f601
Revises: a1b2c3d4e5f6
Create Date: 2026-02-21 10:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "b2c3d4e5f601"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "deployments",
        sa.Column("fetch_status", sa.String(50), nullable=True),
    )
    op.create_index(
        "ix_deployments_fetch_status",
        "deployments",
        ["fetch_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_deployments_fetch_status", table_name="deployments")
    op.drop_column("deployments", "fetch_status")
