"""Versioned secret binding, protected import placeholders and controller metadata backups

Revision ID: 0003_bindings
Revises: 0002_invariants
"""
import sqlalchemy as sa
from alembic import op

revision = '0003_bindings'
down_revision = '0002_invariants'
branch_labels = None
depends_on = None


def upgrade():
    # Rows that exist before this revision, or that an older process inserts during a rolling upgrade,
    # carry binding='unverified' until the explicit binding migration proves/upgrades each envelope.
    with op.batch_alter_table('secrets') as batch:
        batch.add_column(sa.Column('binding', sa.String(length=20), nullable=False, server_default='unverified'))
        batch.create_check_constraint('secret_binding', "binding IN ('row','unverified')")
    with op.batch_alter_table('controller_state') as batch:
        batch.add_column(sa.Column('controller_id', sa.String(length=36), nullable=True))
    with op.batch_alter_table('instances') as batch:
        batch.alter_column('host_id', existing_type=sa.String(length=36), nullable=True)
    with op.batch_alter_table('repositories') as batch:
        batch.add_column(sa.Column('purpose', sa.String(length=20), nullable=False, server_default='instance'))
        batch.alter_column('instance_id', existing_type=sa.String(length=36), nullable=True)
        batch.create_check_constraint('repository_purpose', "purpose IN ('instance','controller')")
        batch.create_check_constraint('repository_instance_purpose', "(purpose = 'controller') = (instance_id IS NULL)")
    op.create_index('controller_repository_destination', 'repositories', ['destination_id'], unique=True,
                    postgresql_where=sa.text("purpose = 'controller'"), sqlite_where=sa.text("purpose = 'controller'"))
    op.create_table('controller_backups',
    sa.Column('job_id', sa.String(length=36), nullable=False),
    sa.Column('destination_id', sa.String(length=36), nullable=False),
    sa.Column('repository_id', sa.String(length=36), nullable=False),
    sa.Column('snapshot_uuid', sa.String(length=36), nullable=False),
    sa.Column('restic_snapshot_id', sa.String(length=64), nullable=True),
    sa.Column('manifest_hash', sa.String(length=64), nullable=True),
    sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('state', sa.String(length=30), nullable=False),
    sa.Column('alembic_version', sa.String(length=64), nullable=True),
    sa.Column('tables', sa.Integer(), nullable=False),
    sa.Column('rows', sa.Integer(), nullable=False),
    sa.Column('bytes', sa.BigInteger(), nullable=False),
    sa.Column('pg_dump_included', sa.Boolean(), nullable=False),
    sa.Column('error_code', sa.String(length=80), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['destination_id'], ['storage_destinations.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['job_id'], ['jobs.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('job_id'),
    sa.UniqueConstraint('snapshot_uuid')
    )


def downgrade():
    op.drop_table('controller_backups')
    op.drop_index('controller_repository_destination', table_name='repositories')
    with op.batch_alter_table('repositories') as batch:
        batch.drop_constraint('repository_instance_purpose', type_='check')
        batch.drop_constraint('repository_purpose', type_='check')
        batch.alter_column('instance_id', existing_type=sa.String(length=36), nullable=False)
        batch.drop_column('purpose')
    with op.batch_alter_table('instances') as batch:
        batch.alter_column('host_id', existing_type=sa.String(length=36), nullable=False)
    with op.batch_alter_table('controller_state') as batch:
        batch.drop_column('controller_id')
    with op.batch_alter_table('secrets') as batch:
        batch.drop_constraint('secret_binding', type_='check')
        batch.drop_column('binding')
