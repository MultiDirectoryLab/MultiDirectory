"""Add OU 'computers' if it doesn't exist.

Revision ID: 8164b4a9e1f1
Revises: eeaed5989eb0
Create Date: 2025-09-24 09:37:33.334259

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import delete, exists, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from constants import COMPUTERS_CONTAINER_NAME
from entities import Directory
from ldap_protocol.ldap_schema.attribute_value_validator import (
    AttributeValueValidator,
)
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.role_dao import RoleDAO
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision = "8164b4a9e1f1"
down_revision = "4798b12b97aa"
branch_labels: None | str = None
depends_on: None = None


_OU_COMPUTERS_DATA = {
    "name": COMPUTERS_CONTAINER_NAME,
    "object_class": "organizationalUnit",
    "attributes": {"objectClass": ["top", "container"]},
    "children": [],
}


@temporary_stub_column("is_system", sa.Boolean())
def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""
    from ldap_protocol.auth.setup_gateway import SetupGateway

    async def _create_ou_computers(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        object_class_dao = ObjectClassDAO(session)
        attribute_value_validator = AttributeValueValidator()
        entity_type_dao = EntityTypeDAO(
            session,
            object_class_dao,
            attribute_value_validator=attribute_value_validator,
        )
        setup_gateway = SetupGateway(
            session,
            PasswordUtils(),
            entity_type_dao,
            attribute_value_validator=attribute_value_validator,
        )

        base_directories = await get_base_directories(session)
        if not base_directories:
            return
        domain_dir = base_directories[0]

        exists_ou_computers = await session.scalar(
            select(
                exists(Directory)
                .where(qa(Directory.name) == COMPUTERS_CONTAINER_NAME),
            ),
        )  # fmt: skip
        if exists_ou_computers:
            return

        await setup_gateway.create_dir(
            _OU_COMPUTERS_DATA,
            is_system=True,
            domain=domain_dir,
            parent=domain_dir,
        )

        ou_computers_dir = await session.scalar(
            select(Directory)
            .where(qa(Directory.name) == COMPUTERS_CONTAINER_NAME),
        )  # fmt: skip
        if not ou_computers_dir:
            raise Exception("Directory 'ou=computers' not found.")

        await role_use_case.inherit_parent_aces(
            parent_directory=domain_dir,
            directory=ou_computers_dir,
        )

        await session.commit()

    op.run_async(_create_ou_computers)


@temporary_stub_column("is_system", sa.Boolean())
def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""

    async def _delete_ou_computers(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        await session.execute(
            delete(Directory)
            .where(qa(Directory.name) == COMPUTERS_CONTAINER_NAME),
        )  # fmt: skip

        await session.commit()

    op.run_async(_delete_ou_computers)
