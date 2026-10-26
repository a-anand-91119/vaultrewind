"""Durable scheduling policy for controller metadata backups.

Revision ID: 0005_controller_backup_policy
Revises: 0004_fence64
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_controller_backup_policy"
down_revision = "0004_fence64"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "controller_backup_policies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("destination_id", sa.String(length=36), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("schedule_kind", sa.String(length=20), nullable=False),
        sa.Column("timezone", sa.String(length=80), nullable=False),
        sa.Column("daily_time", sa.String(length=5), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["destination_id"], ["storage_destinations.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("destination_id", name="controller_backup_policy_destination"),
        sa.CheckConstraint("id = 1", name="controller_backup_policy_singleton"),
        sa.CheckConstraint("schedule_kind = 'daily'", name="controller_backup_policy_schedule"),
    )
    op.create_index(
        "ix_controller_backup_policies_next_run_at", "controller_backup_policies", ["next_run_at"]
    )


def downgrade():
    op.drop_index("ix_controller_backup_policies_next_run_at", table_name="controller_backup_policies")
    op.drop_table("controller_backup_policies")
