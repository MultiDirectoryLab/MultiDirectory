"""Add directory is_system column.

Revision ID: 818083218568
Revises: 6c858cc05da7
Create Date: 2025-12-25 08:58:20.074356

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import Session

from constants import (
    COMPUTERS_CONTAINER_NAME,
    DOMAIN_ADMIN_GROUP_NAME,
    DOMAIN_COMPUTERS_GROUP_NAME,
    DOMAIN_USERS_GROUP_NAME,
    GROUPS_CONTAINER_NAME,
    READ_ONLY_GROUP_NAME,
    USERS_CONTAINER_NAME,
)
from entities import Directory
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "818083218568"
down_revision: None | str = "6c858cc05da7"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    op.add_column(
        "Directory",
        sa.Column("is_system", sa.Boolean(), nullable=True),
    )
    # NOTE: If instances of Directories exists, set default value
    session.execute(update(Directory).values({"is_system": False}))
    op.alter_column("Directory", "is_system", nullable=False)

    async def _indicate_system_directories(
        connection: AsyncConnection,
    ) -> None:
        session = AsyncSession(connection)

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        for base_dn in base_dn_list:
            base_dn.is_system = True

        await session.flush()

        await session.execute(
            update(Directory)
            .where(
                qa(Directory.is_system).is_(False),
                qa(Directory.name).in_(
                    (
                        GROUPS_CONTAINER_NAME,
                        DOMAIN_ADMIN_GROUP_NAME,
                        DOMAIN_USERS_GROUP_NAME,
                        READ_ONLY_GROUP_NAME,
                        DOMAIN_COMPUTERS_GROUP_NAME,
                        COMPUTERS_CONTAINER_NAME,
                        USERS_CONTAINER_NAME,
                        "services",
                        "krbadmin",
                        "kerberos",
                    ),
                ),
            )
            .values(is_system=True),
        )
        await session.flush()

        await session.execute(
            update(Directory)
            .where(
                qa(Directory.is_system).is_(False),
                qa(Directory.object_class) == "user",
            )
            .values(is_system=True),
        )
        await session.flush()

    op.run_async(_indicate_system_directories)


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade."""
    op.drop_column("Directory", "is_system")
