"""Add ReadOnly group and access policy for it.

Revision ID: fafc3d0b11ec
Revises: bf435bbd95ff
Create Date: 2024-11-11 15:21:23.568233

"""
from alembic import op
from sqlalchemy import exists
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.access_policy import create_access_policy, get_policies
from ldap_protocol.utils.queries import (
    create_group,
    get_base_directories,
    get_group,
)
from models import AccessPolicy, Directory

# revision identifiers, used by Alembic.
revision = 'fafc3d0b11ec'
down_revision = 'bf435bbd95ff'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    async def _create_readonly_grp_and_plcy(connection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        has_ro_access_policy = await session.scalars(
            exists(AccessPolicy)
            .where(AccessPolicy.name == 'ReadOnly Access Policy'),
        ).one()
        if has_ro_access_policy:
            await create_access_policy(
                name='ReadOnly Access Policy',
                can_add=False,
                can_modify=False,
                can_read=True,
                can_delete=False,
                grant_dn=base_dn_list[0].path_dn,
                groups=[
                    "cn=readonly domain controllers,cn=groups," +
                    base_dn_list[0].path_dn,
                ],
                session=session,
            )
            await session.flush()

        try:
            group_dir = await session.scalars(
                exists(Directory)
                .where(Directory.name == 'readonly domain controllers'),
            ).one()

            if not group_dir:
                _, group = await create_group(
                    'readonly domain controllers', 521, session)

            await session.flush()
        except (IntegrityError, DBAPIError):
            pass

        await session.commit()
        await session.close()

    op.run_async(_create_readonly_grp_and_plcy)


def downgrade() -> None:
    """Downgrade."""
    async def _delete_readonly_grp_and_plcy(connection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        policies = await get_policies(session)
        for policy in policies:
            if policy.name == 'ReadOnly Access Policy':
                await session.delete(policy)
                await session.flush()

        group_dir = await get_group(
            "cn=readonly domain controllers,cn=groups," +
            base_dn_list[0].path_dn,
        )

        if group_dir is not None:
            await session.delete(group_dir)
            await session.flush()

        await session.commit()

    op.run_async(_delete_readonly_grp_and_plcy)