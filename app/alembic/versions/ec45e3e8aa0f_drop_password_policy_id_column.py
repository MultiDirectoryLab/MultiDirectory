"""Drop unused Directory.password_policy_id column.

Revision ID: ec45e3e8aa0f
Revises: a1b2c3d4e5f6
Create Date: 2026-01-20 14:33:36.236135

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer

# revision identifiers, used by Alembic.
revision: None | str = "ec45e3e8aa0f"
down_revision: None | str = "a1b2c3d4e5f6"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""
    op.drop_constraint(op.f("Directory_password_policy_id_fkey"), "Directory", type_="foreignkey")
    op.drop_column("Directory", "password_policy_id")


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""
    op.add_column("Directory", sa.Column("password_policy_id", sa.INTEGER(), autoincrement=False, nullable=True))
    op.create_foreign_key(
        op.f("Directory_password_policy_id_fkey"), "Directory", "PasswordPolicies", ["password_policy_id"], ["id"]
    )
