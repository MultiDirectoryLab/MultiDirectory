"""Add OU 'Domain Controllers' if it does not exist.

Revision ID: ebf19750805e
Revises: 2dadf40c026a
Create Date: 2026-02-17 08:52:28.048004

"""

from typing import Any

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import delete, exists, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from config import Settings
from constants import DOMAIN_CONTROLLERS_OU_NAME
from entities import Directory
from enums import SamAccountTypeCodes
from ldap_protocol.auth.setup_gateway import SetupGateway
from ldap_protocol.objects import UserAccountControlFlag
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "ebf19750805e"
down_revision: None | str = "2dadf40c026a"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


_OU_DOMAIN_CONTROLLERS_DATA: dict[str, Any] = {
    "name": DOMAIN_CONTROLLERS_OU_NAME,
    "object_class": "organizationalUnit",
    "attributes": {"objectClass": ["top", "container"]},
}


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""

    async def _create_domain_controllers_ou(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            settings = await cnt.get(Settings)
            session = await cnt.get(AsyncSession)
            setup_gateway = await cnt.get(SetupGateway)
            role_use_case = await cnt.get(RoleUseCase)

        base_directories = await get_base_directories(session)
        if not base_directories:
            return
        domain_dir = base_directories[0]

        exists_dc_ou = await session.scalar(
            select(
                exists(Directory)
                .where(qa(Directory.name) == DOMAIN_CONTROLLERS_OU_NAME),
            ),
        )  # fmt: skip
        if exists_dc_ou:
            return

        domain_controller_data = [
            {
                "name": settings.HOST_MACHINE_SHORT_NAME,
                "object_class": "computer",
                "attributes": {
                    "objectClass": ["top"],
                    "userAccountControl": [
                        str(
                            UserAccountControlFlag.SERVER_TRUST_ACCOUNT.value,
                        ),
                    ],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_MACHINE_ACCOUNT),
                    ],
                    "sAMAccountName": [settings.HOST_MACHINE_SHORT_NAME],
                    "ipHostNumber": [settings.DEFAULT_NAMESERVER],
                },
            },
        ]
        _OU_DOMAIN_CONTROLLERS_DATA["children"] = domain_controller_data

        await setup_gateway.create_dir(
            _OU_DOMAIN_CONTROLLERS_DATA,
            is_system=True,
            domain=domain_dir,
            parent=domain_dir,
        )

        dc_ou = await session.scalar(
            select(Directory).where(
                qa(Directory.name) == DOMAIN_CONTROLLERS_OU_NAME,
            ),
        )
        if not dc_ou:
            raise Exception("Domain Controllers OU was not created")

        dc = await session.scalar(
            select(Directory).where(
                qa(Directory.name) == settings.HOST_MACHINE_SHORT_NAME,
            ),
        )
        if not dc:
            raise Exception("Domain Controller was not created")

        await role_use_case.inherit_parent_aces(
            parent_directory=domain_dir,
            directory=dc_ou,
        )
        await role_use_case.inherit_parent_aces(
            parent_directory=dc_ou,
            directory=dc,
        )

        await session.commit()

    op.run_async(_create_domain_controllers_ou)


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""

    async def _delete_domain_controllers_ou(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        domain_controller_ou = await session.scalar(
            select(Directory).where(
                qa(Directory.name) == DOMAIN_CONTROLLERS_OU_NAME,
            ),
        )

        if not domain_controller_ou:
            return

        await session.execute(
            delete(Directory).where(
                qa(Directory.parent_id) == domain_controller_ou.id,
            ),
        )

        await session.execute(
            delete(Directory).where(
                qa(Directory.id) == domain_controller_ou.id,
            ),
        )
        await session.commit()

    op.run_async(_delete_domain_controllers_ou)
