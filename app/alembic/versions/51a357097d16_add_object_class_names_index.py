"""Add GIN index for object_class_names.

Revision ID: 51a357097d16
Revises: 35d1542d2505
Create Date: 2025-07-21 12:18:06.425661

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "51a357097d16"
down_revision = "35d1542d2505"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.execute(
        sa.text(
            """
            CREATE INDEX lw_object_class_names
            ON "EntityTypes" USING GIN(array_lowercase("object_class_names"));
            """,
        ),
    )


def downgrade() -> None:
    """Downgrade."""
    op.execute(sa.text("DROP INDEX lw_object_class_names"))
