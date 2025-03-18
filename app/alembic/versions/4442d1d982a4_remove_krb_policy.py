"""Remove default_policy.

Revision ID: 4442d1d982a4
Revises: 692ae64e0cc5
Create Date: 2025-02-28 12:01:56.745334

"""

from alembic import op
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from models import Attribute, Directory

# revision identifiers, used by Alembic.
revision = "4442d1d982a4"
down_revision = "692ae64e0cc5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    default_policy = session.scalar(
        select(Directory)
        .where(Directory.name == "default_policy")
    )  # fmt: skip

    if not default_policy:
        return

    session.delete(default_policy)
    session.execute(
        delete(Attribute)
        .where(Attribute.name == "krbpwdpolicyreference")
    )  # fmt: skip


def downgrade() -> None:
    """Downgrade."""
