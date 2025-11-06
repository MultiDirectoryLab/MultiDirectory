"""Add OU 'computers' if it doesn't exist.

Revision ID: 8164b4a9e1f1
Revises: eeaed5989eb0
Create Date: 2025-09-24 09:37:33.334259

"""

from alembic import op
from sqlalchemy import delete, exists, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Directory
from ldap_protocol.identity.setup_gateway import SetupGateway
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.role_dao import RoleDAO
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.queries import get_base_directories
from password_manager.password_validator import PasswordValidator
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision = "8164b4a9e1f1"
down_revision = "4798b12b97aa"
branch_labels: None | str = None
depends_on: None = None


_OU_COMPUTERS_DATA = {
    "name": "computers",
    "object_class": "organizationalUnit",
    "attributes": {"objectClass": ["top", "container"]},
    "children": [],
}


def upgrade() -> None:
    """Upgrade."""

    async def _create_ou_computers(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        object_class_dao = ObjectClassDAO(session)
        entity_type_dao = EntityTypeDAO(session, object_class_dao)
        setup_gateway = SetupGateway(
            session,
            PasswordValidator(),
            entity_type_dao,
        )

        base_directories = await get_base_directories(session)
        if not base_directories:
            return
        domain_dir = base_directories[0]

        exists_ou_computers = await session.scalar(
            select(
                exists(Directory)
                .where(qa(Directory.name) == "computers"),
            ),
        )  # fmt: skip
        if exists_ou_computers:
            return

        await setup_gateway.create_dir(
            _OU_COMPUTERS_DATA,
            domain_dir,
            domain_dir,
        )

        ou_computers_dir = await session.scalar(
            select(Directory)
            .where(qa(Directory.name) == "computers"),
        )  # fmt: skip
        if not ou_computers_dir:
            raise Exception("Directory 'ou=computers' not found.")

        role_dao = RoleDAO(session)
        ace_dao = AccessControlEntryDAO(session)
        role_use_case = RoleUseCase(role_dao, ace_dao)
        await role_use_case.inherit_parent_aces(
            parent_directory=domain_dir,
            directory=ou_computers_dir,
        )

        await session.commit()

    op.run_async(_create_ou_computers)


def downgrade() -> None:
    """Downgrade."""

    async def _delete_ou_computers(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        await session.execute(
            delete(Directory)
            .where(qa(Directory.name) == "computers"),
        )  # fmt: skip

        await session.commit()

    op.run_async(_delete_ou_computers)
