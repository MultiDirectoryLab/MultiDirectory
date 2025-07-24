"""index_single_level.

Revision ID: a7971f00ba4d
Revises: 35d1542d2505
Create Date: 2025-07-22 11:13:48.397808

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a7971f00ba4d"
down_revision = "35d1542d2505"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create index for Directory depth field."""
    op.execute(
        sa.text(
            "CREATE INDEX IF NOT EXISTS idx_Directory_depth_hash "
            'ON "Directory" '
            "USING hash (depth);"
        )
    )
    op.execute(
        sa.text(
            "CREATE INDEX idx_composite_attributes_directory_id_name "
            'ON "Attributes" ("directoryId", lower("name"));'
        )
    )


def downgrade() -> None:
    """Remove indexes for Directory depth field and Attributes table."""
    op.drop_index(
        op.f("idx_Directory_depth_hash"),
        table_name="Directory",
        if_exists=True,
    )
    op.drop_index(
        "idx_composite_attributes_directory_id_name",
        table_name="Attributes",
        if_exists=True,
    )
