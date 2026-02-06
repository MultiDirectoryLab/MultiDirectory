"""Add directory is_system column.

Revision ID: 71e642808369
Revises: a99f866a7e3a
Create Date: 2026-01-15 09:08:12.866533

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import Session

from constants import (
    DOMAIN_ADMIN_GROUP_NAME,
    DOMAIN_COMPUTERS_GROUP_NAME,
    DOMAIN_USERS_GROUP_NAME,
    READ_ONLY_GROUP_NAME,
)
from entities import Directory
from ldap_protocol.utils.queries import get_base_directories
from infrasture.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "71e642808369"
down_revision: None | str = "a99f866a7e3a"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:
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
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        await session.execute(
            update(Directory)
            .where(
                qa(Directory.parent_id).is_(None),
            )
            .values(is_system=True),
        )

        await session.flush()

        await session.execute(
            update(Directory)
            .where(
                qa(Directory.is_system).is_(False),
                qa(Directory.name).in_(
                    (
                        "groups",
                        DOMAIN_ADMIN_GROUP_NAME,
                        DOMAIN_USERS_GROUP_NAME,
                        READ_ONLY_GROUP_NAME,
                        DOMAIN_COMPUTERS_GROUP_NAME,
                        "computers",
                        "users",
                        "services",
                        "krbadmin",
                        "kerberos",
                    ),
                ),
            )
            .values(is_system=True),
        )
        await session.flush()

        # NOTE: It's required to mark only administrator users as system.
        # Because only main administrator has object_class=='user'.
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
