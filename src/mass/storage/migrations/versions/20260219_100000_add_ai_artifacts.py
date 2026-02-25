"""Add AI artifact tables and finding verification columns.

Creates guardrail_sets and explanations tables for persisting
AI-generated outputs. Adds verification columns to findings table.

Per roadmap Phase 2.1-2.2 — AI Output Persistence.

Revision ID: a1b2c3d4e5f6
Revises: f8a9b0c1d2e3
Create Date: 2026-02-19 10:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "f8a9b0c1d2e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # -- guardrail_sets table --
    op.create_table(
        "guardrail_sets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("target_name", sa.String(255), nullable=False, server_default=""),
        sa.Column("provider", sa.String(100), nullable=False, server_default=""),
        sa.Column("model_used", sa.String(255), nullable=False, server_default=""),
        sa.Column("findings_analyzed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_multiplier", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(50), nullable=True),
        sa.Column("risk_factors", sa.Text(), nullable=True),
        sa.Column("registry_guardrails", sa.Text(), nullable=True),
        sa.Column("ai_guardrails", sa.Text(), nullable=True),
        sa.Column("policies", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_guardrail_sets_tenant_id", "guardrail_sets", ["tenant_id"])
    op.create_index("ix_guardrail_sets_scan_id", "guardrail_sets", ["scan_id"])

    # -- explanations table --
    op.create_table(
        "explanations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("explanation_type", sa.String(50), nullable=False),
        sa.Column("audience", sa.String(50), nullable=False, server_default="developer"),
        sa.Column("depth", sa.String(50), nullable=False, server_default="standard"),
        sa.Column("generated_by", sa.String(50), nullable=False, server_default="template"),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_explanations_tenant_id", "explanations", ["tenant_id"])
    op.create_index("ix_explanations_scan_id", "explanations", ["scan_id"])
    op.create_index("ix_explanations_finding_id", "explanations", ["finding_id"])

    # -- Finding verification columns (P2.2) --
    op.add_column("findings", sa.Column("verification_status", sa.String(50), nullable=True))
    op.add_column("findings", sa.Column("verification_model", sa.String(255), nullable=True))
    op.add_column("findings", sa.Column("verification_reasoning", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("verified_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "verified_at")
    op.drop_column("findings", "verification_reasoning")
    op.drop_column("findings", "verification_model")
    op.drop_column("findings", "verification_status")

    op.drop_index("ix_explanations_finding_id", "explanations")
    op.drop_index("ix_explanations_scan_id", "explanations")
    op.drop_index("ix_explanations_tenant_id", "explanations")
    op.drop_table("explanations")

    op.drop_index("ix_guardrail_sets_scan_id", "guardrail_sets")
    op.drop_index("ix_guardrail_sets_tenant_id", "guardrail_sets")
    op.drop_table("guardrail_sets")
