"""Add remediation_templates table

Revision ID: a3f1b2c4d5e6
Revises: d2e02909d292
Create Date: 2026-02-03 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3f1b2c4d5e6'
down_revision: Union[str, None] = 'd2e02909d292'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'remediation_templates',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('category', sa.String(255), nullable=False),
        sa.Column('subcategory', sa.String(255), nullable=True),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity_default', sa.String(50), nullable=True),
        sa.Column('steps', sa.Text(), nullable=True),
        sa.Column('guardrail_examples', sa.Text(), nullable=True),
        sa.Column('code_examples', sa.Text(), nullable=True),
        sa.Column('cwe_ids', sa.Text(), nullable=True),
        sa.Column('owasp_ids', sa.Text(), nullable=True),
        sa.Column('mitre_ids', sa.Text(), nullable=True),
        sa.Column('references', sa.Text(), nullable=True),
        sa.Column('estimated_effort', sa.String(50), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('meta', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_index(
        'ix_remediation_templates_category',
        'remediation_templates',
        ['category'],
    )
    op.create_index(
        'ix_remediation_templates_subcategory',
        'remediation_templates',
        ['subcategory'],
    )
    op.create_unique_constraint(
        'uq_remediation_category_subcategory',
        'remediation_templates',
        ['category', 'subcategory'],
    )


def downgrade() -> None:
    op.drop_table('remediation_templates')
