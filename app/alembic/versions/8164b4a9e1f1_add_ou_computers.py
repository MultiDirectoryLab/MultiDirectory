"""Add OU 'computers' if it doesn't exist.

Revision ID: 8164b4a9e1f1
Revises: eeaed5989eb0
Create Date: 2025-09-24 09:37:33.334259

"""

from alembic import op
from sqlalchemy import delete, exists, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import selectinload

from extra.setup_dev import create_dir
from ldap_protocol.roles.role_use_case import RoleConstants
from ldap_protocol.utils.queries import get_base_directories
from models import AccessControlEntryDirectoryMembership, Directory, Role
from password_manager.password_validator import PasswordValidator

# revision identifiers, used by Alembic.
revision = "8164b4a9e1f1"
down_revision = "eeaed5989eb0"
branch_labels = None
depends_on = None


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

        if not await get_base_directories(session):
            return

        exists_ou_computers = await session.scalar(
            select(
                exists(Directory)
                .where(Directory.name == "computers"),
            ),
        )  # fmt: skip
        if exists_ou_computers:
            return

        domain_dir = await session.scalar(
            select(Directory)
            .where(Directory.parent_id.is_(None)),
        )  # fmt: skip

        await create_dir(
            _OU_COMPUTERS_DATA,
            session,
            domain_dir,
            PasswordValidator(),
            domain_dir,
        )

        ou_computers_dir_id = await session.scalar(
            select(Directory.id)
            .where(Directory.name == "computers"),
        )  # fmt: skip

        role_names = (
            RoleConstants.DOMAIN_ADMINS_ROLE_NAME,
            RoleConstants.READ_ONLY_ROLE_NAME,
        )
        roles_res = await session.scalars(
            select(Role)
            .where(Role.name.in_((role_names)))
            .options(selectinload(Role.access_control_entries)),
        )
        roles = roles_res.all()

        members = [
            AccessControlEntryDirectoryMembership(
                access_control_entry_id=ace.id,
                directory_id=ou_computers_dir_id,
            )
            for role in roles
            for ace in role.access_control_entries
        ]
        session.add_all(members)

        await session.commit()
        await session.close()

    op.run_async(_create_ou_computers)


def downgrade() -> None:
    """Downgrade."""

    async def _delete_ou_computers(connection: AsyncSession) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        await session.execute(
            delete(Directory)
            .where(Directory.name == "computers"),
        )  # fmt: skip

        await session.commit()

    op.run_async(_delete_ou_computers)
