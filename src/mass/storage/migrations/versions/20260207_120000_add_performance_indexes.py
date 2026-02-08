"""Add performance indexes for tenant-scoped queries.

PostgreSQL does NOT auto-create indexes on foreign-key columns.
These composite indexes cover the hot query patterns:
  - Dashboard stats aggregation (scans by tenant+status)
  - Scan listing by deployment (ordered by date)
  - Finding breakdown by scan+severity and scan+category
  - Open-findings count across tenant
  - API key auth lookup by prefix
  - Report listing by scan and tenant

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
Create Date: 2026-02-07 12:00:00.000000
"""

from typing import Sequence, Union

from alembic import op

revision: str = "f8a9b0c1d2e3"
down_revision: Union[str, None] = "e7f8a9b0c1d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -- deployments --
    op.create_index("ix_deployments_tenant", "deployments", ["tenant_id"])

    # -- scans --
    op.create_index("ix_scans_tenant_status", "scans", ["tenant_id", "status"])
    # DESC index for "recent scans" queries — raw SQL for sort direction
    op.execute(
        "CREATE INDEX ix_scans_tenant_created ON scans (tenant_id, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_scans_deployment_created ON scans (deployment_id, created_at DESC)"
    )

    # -- findings --
    op.create_index(
        "ix_findings_scan_severity", "findings", ["scan_id", "severity"]
    )
    op.create_index(
        "ix_findings_scan_category", "findings", ["scan_id", "category"]
    )
    op.create_index(
        "ix_findings_tenant_status", "findings", ["tenant_id", "status"]
    )

    # -- reports --
    op.create_index("ix_reports_scan", "reports", ["scan_id"])
    op.create_index("ix_reports_tenant", "reports", ["tenant_id"])

    # -- api_keys (prefix lookup is the auth hot path) --
    op.create_index("ix_api_keys_prefix", "api_keys", ["prefix"])
    op.create_index("ix_api_keys_tenant", "api_keys", ["tenant_id"])

    # -- users --
    op.create_index("ix_users_tenant", "users", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_users_tenant", table_name="users")
    op.drop_index("ix_api_keys_tenant", table_name="api_keys")
    op.drop_index("ix_api_keys_prefix", table_name="api_keys")
    op.drop_index("ix_reports_tenant", table_name="reports")
    op.drop_index("ix_reports_scan", table_name="reports")
    op.drop_index("ix_findings_tenant_status", table_name="findings")
    op.drop_index("ix_findings_scan_category", table_name="findings")
    op.drop_index("ix_findings_scan_severity", table_name="findings")
    op.drop_index("ix_scans_deployment_created", table_name="scans")
    op.drop_index("ix_scans_tenant_created", table_name="scans")
    op.drop_index("ix_scans_tenant_status", table_name="scans")
    op.drop_index("ix_deployments_tenant", table_name="deployments")
