"""Update krbadmin userAccountControl attribute.

Revision ID: 6303f5c706ec
Revises: 93ba193c6a53
Create Date: 2025-10-24 15:33:31.478490

"""

from alembic import op
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import joinedload

from entities import Attribute, Directory
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.helpers import create_integer_hash
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

    async def _change_uid_admin(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        directory = await session.scalar(
            select(Directory)
            .join(qa(Directory.attributes))
            .where(
                qa(Attribute.name) == "uidNumber",
                qa(Attribute.value) == "1000",
            )
            .options(joinedload(qa(Directory.user))),
        )  # fmt: skip

        if not directory:
            return

        if not directory.user or not directory.user.sam_account_name:
            return

        await session.execute(
            update(Attribute)
            .where(
                qa(Attribute.directory_id) == directory.id,
                qa(Attribute.name) == "uidNumber",
            )
            .values(
                value=str(
                    create_integer_hash(directory.user.sam_account_name),
                ),
            ),
        )
        await session.commit()

    op.run_async(_update_krbadmin_uac)
    op.run_async(_change_uid_admin)


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
