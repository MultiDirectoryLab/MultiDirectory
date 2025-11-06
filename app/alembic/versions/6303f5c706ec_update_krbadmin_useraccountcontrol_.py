"""Update krbadmin userAccountControl attribute.

Revision ID: 6303f5c706ec
Revises: 93ba193c6a53
Create Date: 2025-10-24 15:33:31.478490

"""

from alembic import op
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Attribute, Directory
from ldap_protocol.user_account_control import UserAccountControlFlag
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "6303f5c706ec"
down_revision: None | str = "ad52bc16b87d"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade() -> None:
    """Upgrade."""

    async def _update_krbadmin_uac(connection: AsyncConnection) -> None:
        session = AsyncSession(connection)
        await session.begin()

        krbadmin_user_dir = await session.scalar(
            select(Directory)
            .filter_by(name="krbadmin")
            .join(qa(Directory.user)),
        )

        if krbadmin_user_dir:
            await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.directory_id) == krbadmin_user_dir.id,
                    qa(Attribute.name) == "userAccountControl",
                )
                .values(
                    value=str(
                        UserAccountControlFlag.NORMAL_ACCOUNT
                        + UserAccountControlFlag.DONT_EXPIRE_PASSWORD,
                    ),
                ),
            )

    op.run_async(_update_krbadmin_uac)


def downgrade() -> None:
    """Downgrade."""

    async def _downgrade_krbadmin_uac(connection: AsyncConnection) -> None:
        session = AsyncSession(connection)
        await session.begin()

        krbadmin_user_dir = await session.scalar(
            select(Directory)
            .filter_by(name="krbadmin")
            .join(qa(Directory.user)),
        )

        if krbadmin_user_dir:
            await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.directory_id) == krbadmin_user_dir.id,
                    qa(Attribute.name) == "userAccountControl",
                )
                .values(
                    value=str(UserAccountControlFlag.NORMAL_ACCOUNT),
                ),
            )

    op.run_async(_downgrade_krbadmin_uac)
