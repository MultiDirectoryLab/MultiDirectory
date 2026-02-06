"""Delete rsops and incorrect gpos.

Revision ID: c007129b7973
Revises: 8164b4a9e1f1
Create Date: 2025-10-03 09:35:10.399265

"""

from dishka import AsyncContainer

# revision identifiers, used by Alembic.
revision: None | str = "c007129b7973"
down_revision: None | str = "8164b4a9e1f1"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""
