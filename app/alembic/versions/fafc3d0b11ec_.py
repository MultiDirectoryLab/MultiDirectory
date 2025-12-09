"""Add ReadOnly group and access policy for it.

Revision ID: fafc3d0b11ec
Revises: bf435bbd95ff
Create Date: 2024-11-11 15:21:23.568233

"""

from alembic import op
from sqlalchemy import delete, exists, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Directory
from extra.alembic_utils import temporary_stub_entity_type_name
from ldap_protocol.ldap_schema.attribute_value_validator import (
    AttributeValueValidator,
)
from ldap_protocol.utils.queries import (
    create_group,
    get_base_directories,
    get_search_path,
)
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision = "fafc3d0b11ec"
down_revision = "bf435bbd95ff"
branch_labels: None | str = None
depends_on: None | str = None


@temporary_stub_entity_type_name
def upgrade() -> None:
    """Upgrade."""

    async def _create_readonly_grp_and_plcy(
        connection: AsyncConnection,
    ) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        try:
            group_dir_query = select(
                exists(Directory).where(
                    qa(Directory.name) == "readonly domain controllers",
                ),
            )
            group_dir = (await session.scalars(group_dir_query)).one()

            if not group_dir:
                dir_, _ = await create_group(
                    name="readonly domain controllers",
                    sid=521,
                    attribute_value_validator=AttributeValueValidator(),
                    session=session,
                )

            await session.flush()
        except (IntegrityError, DBAPIError):
            pass

        await session.commit()
        await session.close()

    op.run_async(_create_readonly_grp_and_plcy)


@temporary_stub_entity_type_name
def downgrade() -> None:
    """Downgrade."""

    async def _delete_readonly_grp_and_plcy(
        connection: AsyncConnection,
    ) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        group_dn = (
            "cn=readonly domain controllers,cn=groups,"
            + base_dn_list[0].path_dn
        )

        await session.execute(
            delete(Directory)
            .filter_by(path=get_search_path(group_dn)),
        )  # fmt: skip

        await session.commit()

    op.run_async(_delete_readonly_grp_and_plcy)
