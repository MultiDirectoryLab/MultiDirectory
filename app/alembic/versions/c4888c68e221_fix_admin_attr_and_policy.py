"""Hotfix.

Revision ID: c4888c68e221
Revises: 93ba193c6a53
Create Date: 2025-11-06 10:38:31.124118

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import joinedload

from entities import Attribute, Directory, NetworkPolicy
from ldap_protocol.ldap_schema.attribute_value_validator import (
    AttributeValueValidator,
)
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.helpers import create_integer_hash
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "c4888c68e221"
down_revision: None | str = "93ba193c6a53"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade() -> None:
    """Upgrade."""

    async def _attach_entity_type_to_directories(
        connection: AsyncConnection,
    ) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        if not await get_base_directories(session):
            return

        object_class_dao = ObjectClassDAO(
            session,
        )
        entity_type_dao = EntityTypeDAO(
            session,
            object_class_dao=object_class_dao,
            attribute_value_validator=AttributeValueValidator(),
        )
        await entity_type_dao.attach_entity_type_to_directories()
        await session.commit()

    async def _change_uid_admin(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        directory = await session.scalar(
            sa.select(Directory)
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
        await session.commit()

    async def _change_ldap_session_ttl(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        await session.execute(
            sa.update(NetworkPolicy)
            .where(
                qa(NetworkPolicy.name) == "Default open policy",
            )
            .values(
                ldap_session_ttl=7200,
            ),
        )
        await session.commit()

    op.run_async(_change_uid_admin)
    op.run_async(_change_ldap_session_ttl)
    op.run_async(_attach_entity_type_to_directories)


def downgrade() -> None:
    """Downgrade."""
