"""empty message.

Revision ID: a55d556094d9
Revises: 16a9fa2c1f1e
Create Date: 2025-12-01 15:41:06.764130

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: None | str = "a55d556094d9"
down_revision: None | str = "16a9fa2c1f1e"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade() -> None:
    """Upgrade."""
    op.create_index(
        "idx_attributes_value_distinguished_name",
        "Attributes",
        ["value"],
        unique=True,
        postgresql_where=sa.text("lower(name::text) = 'distinguishedname'"),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_index(
        "idx_attributes_value_distinguished_name",
        table_name="Attributes",
        postgresql_where=sa.text("lower(name::text) = 'distinguishedname'"),
    )
