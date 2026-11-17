"""logic_group_values: the list columns of logic_groups as rows, for search filters and facets

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-15

Derived data: the upgrade fills the table from the logic_groups already in the database, so search works without
a reindex; `suriharvest index` rebuilds it with logic_groups. The downgrade drops it (nothing else refers to it):
`alembic downgrade 0001` with the configuration from `suriharvest.db.alembic_config`, then run the older version.
"""

from alembic import op
import sqlalchemy as sa


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None

KINDS = ("buffers", "sources", "flags", "loads_in", "fails_in", "mitre")


def upgrade() -> None:
    op.create_table('logic_group_values',
    sa.Column('group_id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=10), nullable=False),
    sa.Column('pos', sa.Integer(), nullable=False),
    sa.Column('value', sa.Text(), nullable=True),
    sa.Column('lvalue', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('group_id', 'kind', 'pos'),
    sqlite_with_rowid=False
    )
    with op.batch_alter_table('logic_group_values', schema=None) as batch_op:
        batch_op.create_index('ix_logic_group_values_lookup', ['kind', 'lvalue'], unique=False)
    for kind in KINDS:  # same statement as suriharvest.index.fill_values (a migration does not import app code)
        op.execute(
            "INSERT INTO logic_group_values(group_id, kind, pos, value, lvalue) "
            f"SELECT g.id, '{kind}', j.key, j.value, lower(j.value) FROM logic_groups g, json_each(g.{kind}) j"
        )


def downgrade() -> None:
    with op.batch_alter_table('logic_group_values', schema=None) as batch_op:
        batch_op.drop_index('ix_logic_group_values_lookup')
    op.drop_table('logic_group_values')
