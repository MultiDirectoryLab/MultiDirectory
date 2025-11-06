"""Hotfix.

Revision ID: c4888c68e221
Revises: 93ba193c6a53
Create Date: 2025-11-06 10:38:31.124118

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Attribute, Directory
from ldap_protocol.utils.helpers import create_integer_hash
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "c4888c68e221"
down_revision: None | str = "93ba193c6a53"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade() -> None:
    """Upgrade."""

    async def change_uid_admin(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        directory = await session.scalar(
            sa.select(Directory)
            .join(qa(Directory.user))
            .join(qa(Directory.attributes))
            .where(
                qa(Attribute.name) == "uidNumber",
                qa(Attribute.value) == "1000",
            ),
        )  # fmt: skip

        if not directory:
            return

        await session.execute(
            sa.update(Attribute)
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

    op.run_async(change_uid_admin)


def downgrade() -> None:
    """Downgrade."""
    op.alter_column(
        "EntityTypes",
        "object_class_names",
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        nullable=False,
    )
