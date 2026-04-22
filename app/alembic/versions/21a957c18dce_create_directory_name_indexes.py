"""Create Directory.name indexes.

Revision ID: 21a957c18dce
Revises: 1b71cafba681
Create Date: 2026-04-10 11:15:22.133564

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer

# revision identifiers, used by Alembic.
revision: None | str = "21a957c18dce"
down_revision: None | str = "1b71cafba681"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.create_index("idx_Directory_name_hash", "Directory", ["name"], unique=False, postgresql_using="hash")
    op.create_index(
        "idx_Directory_name_gin_trgm",
        "Directory",
        [sa.literal_column("name gin_trgm_ops")],
        unique=False,
        postgresql_using="gin",
    )


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""
    op.drop_index("idx_Directory_name_gin_trgm", table_name="Directory")
    op.drop_index("idx_Directory_name_hash", table_name="Directory")
