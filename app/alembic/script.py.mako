"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""

import sqlalchemy as sa
from alembic import op
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision: None | str = ${repr(up_revision)}
down_revision: None | str = ${repr(down_revision)}
branch_labels: None | list[str] = ${repr(branch_labels)}
depends_on: None | list[str] = ${repr(depends_on)}


def upgrade() -> None:
    """Upgrade."""
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    """Downgrade."""
    ${downgrades if downgrades else "pass"}
