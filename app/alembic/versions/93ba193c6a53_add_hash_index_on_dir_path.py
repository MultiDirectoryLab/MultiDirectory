"""Add hash index on directory path.

Revision ID: 93ba193c6a53
Revises: f1abf7ef2443
Create Date: 2025-10-22 08:25:08.448818

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer

# revision identifiers, used by Alembic.
revision: None | str = "93ba193c6a53"
down_revision: None | str = "f1abf7ef2443"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Upgrade."""
    op.execute(
        sa.text(
            "CREATE INDEX idx_directory_path_hash "
            'ON "Directory" USING HASH(array_lowercase(path));',
        ),
    )


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade."""
    op.execute(sa.text("DROP INDEX idx_directory_path_hash"))
