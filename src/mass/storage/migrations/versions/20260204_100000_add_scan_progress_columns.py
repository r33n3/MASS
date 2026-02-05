"""Add scan progress tracking columns

Revision ID: b4e5f6a7b8c9
Revises: a3f1b2c4d5e6
Create Date: 2026-02-04 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b4e5f6a7b8c9"
down_revision: Union[str, None] = "a3f1b2c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("progress_percent", sa.Float(), nullable=False, server_default="0.0"))
    op.add_column("scans", sa.Column("current_phase", sa.String(100), nullable=True))
    op.add_column("scans", sa.Column("jobs_completed", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("jobs_total", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("scans", "jobs_total")
    op.drop_column("scans", "jobs_completed")
    op.drop_column("scans", "current_phase")
    op.drop_column("scans", "progress_percent")
