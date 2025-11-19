"""Add user api permissions.

Revision ID: 7adbcd97d942
Revises: f24ed0e49df2
Create Date: 2025-11-07 15:15:36.727549

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Directory, Group, User, UserApiPermissions
from enums import AuthoruzationRules
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "7adbcd97d942"
down_revision: None | str = "f24ed0e49df2"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade() -> None:
    """Upgrade."""

    async def _add_api_permissions(connection: AsyncConnection) -> None:
        session = AsyncSession(connection)
        await session.begin()
        query = (
            select(User)
            .join(qa(User.groups))
            .join(qa(Group.directory))
            .filter(
                qa(Directory.name) == "domain admins",
            )
        )
        users = await session.scalars(query)
        permissions = [perm for perm in AuthoruzationRules]

        for user in users:
            session.add(
                UserApiPermissions(
                    user_id=user.id,
                    permissions=permissions,
                ),
            )
        await session.commit()

    op.create_table(
        "UserApiPermissions",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "permissions",
            postgresql.ARRAY(sa.Integer()),
            server_default="{}",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["Users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.run_async(_add_api_permissions)


def downgrade() -> None:
    """Downgrade."""
    op.drop_table("UserApiPermissions")
