"""Add OU 'computers' if it doesn't exist.

Revision ID: 8164b4a9e1f1
Revises: eeaed5989eb0
Create Date: 2025-09-24 09:37:33.334259

"""

from alembic import op
from sqlalchemy import exists, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
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


def upgrade() -> None:
    """Upgrade."""

    async def _create_ou_computers(connection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        ou_computers_res = await session.scalars(
            select(
                exists(Directory)
                .where(Directory.name == "computers"),
            ),
        )  # fmt: skip

        if ou_computers_res.one():
            return

        try:
            parent_res = await session.scalars(
                select(Directory)
                .where(Directory.parent_id.is_(None)),
            )  # fmt: skip
            parent = parent_res.one()

            data = {
                "name": "computers",
                "object_class": "organizationalUnit",
                "attributes": {"objectClass": ["top", "container"]},
                "children": [],
            }
            await create_dir(
                data,
                session,
                parent,
                PasswordValidator(),
                parent,
            )

            ou_computers_res = await session.scalars(
                select(Directory)
                .where(Directory.name == "computers"),
            )  # fmt: skip
            ou_computers = ou_computers_res.one()
            ou_computers_dir_id = ou_computers.id

            roles_res = await session.scalars(
                select(Role)
                .where(
                    Role.name.in_(
                        (
                            RoleConstants.DOMAIN_ADMINS_ROLE_NAME,
                            RoleConstants.READ_ONLY_ROLE_NAME,
                        ),
                    ),
                )
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

            await session.flush()
        except (IntegrityError, DBAPIError):
            pass

        await session.commit()
        await session.close()

    op.run_async(_create_ou_computers)


def downgrade() -> None:
    """Downgrade."""
