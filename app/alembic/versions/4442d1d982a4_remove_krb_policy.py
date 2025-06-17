"""Remove default_policy.

Revision ID: 4442d1d982a4
Revises: 692ae64e0cc5
Create Date: 2025-02-28 12:01:56.745334

"""

from alembic import op
from sqlalchemy import delete
from sqlalchemy.orm import Session

from extra.alembic_utils import temporary_stub_entity_type_id
from models import Attribute, Directory

# revision identifiers, used by Alembic.
revision = "4442d1d982a4"
down_revision = "692ae64e0cc5"
branch_labels = None
depends_on = None


@temporary_stub_entity_type_id
def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)
    session.execute(delete(Directory).filter_by(name="default_policy"))
    session.execute(delete(Attribute).filter_by(name="krbpwdpolicyreference"))


def downgrade() -> None:
    """Downgrade."""
