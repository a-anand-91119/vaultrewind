"""64-bit resource fencing generations

Revision ID: 0004_fence64
Revises: 0003_bindings
"""
import sqlalchemy as sa
from alembic import op

revision = '0004_fence64'
down_revision = '0003_bindings'
branch_labels = None
depends_on = None

COLUMNS = (("job_steps", "fencing_token"), ("jobs", "fencing_token"), ("resource_leases", "generation"))


def upgrade():
    for table, column in COLUMNS:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(column, existing_type=sa.Integer(), type_=sa.BigInteger(), existing_nullable=False)


def downgrade():
    for table, column in COLUMNS:
        maximum = op.get_bind().execute(sa.text(f'SELECT MAX({column}) FROM {table}')).scalar()
        if maximum is not None and maximum > 2**31 - 1:
            raise RuntimeError("Fencing generations exceed 32-bit range; downgrade is unsafe.")
        with op.batch_alter_table(table) as batch:
            batch.alter_column(column, existing_type=sa.BigInteger(), type_=sa.Integer(), existing_nullable=False)
