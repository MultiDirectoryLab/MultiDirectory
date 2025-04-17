"""add sessions ttl.

Revision ID: 4334e2e871a4
Revises: dafg3a4b22ab
Create Date: 2025-02-20 13:01:56.736774

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "4334e2e871a4"
down_revision = "dafg3a4b22ab"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.add_column(
        "Policies",
        sa.Column(
            "ldap_session_ttl",
            sa.Integer(),
            server_default="-1",
            nullable=False,
        ),
    )
    op.add_column(
        "Policies",
        sa.Column(
            "http_session_ttl",
            sa.Integer(),
            server_default="28800",
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_column("Policies", "http_session_ttl")
    op.drop_column("Policies", "ldap_session_ttl")
