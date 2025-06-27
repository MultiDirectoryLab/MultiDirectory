"""Create index for Attribute name field.

Revision ID: fc8b7617c60a
Revises: ba78cef9700a
Create Date: 2025-06-25 13:54:23.300032
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "fc8b7617c60a"
down_revision = "ba78cef9700a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create index for Attribute name field."""
    op.execute(sa.text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
    op.execute(
        sa.text(
            "CREATE INDEX IF NOT EXISTS attr_name_idx_gin "
            'ON "Attributes" USING GIN(name gin_trgm_ops);'
        )
    )
    op.execute(
        sa.text(
            "CREATE INDEX lw_attr_name_btree "
            'ON "Attributes" USING BTREE(lower(name));'
        ),
    )


def downgrade() -> None:
    """Drop index for Attribute name field."""
    op.execute(sa.text("DROP INDEX IF EXISTS attr_name_idx_gin"))
    op.execute(sa.text("DROP INDEX IF EXISTS lw_attr_name_btree"))
    op.execute(sa.text("DROP EXTENSION IF EXISTS pg_trgm"))
