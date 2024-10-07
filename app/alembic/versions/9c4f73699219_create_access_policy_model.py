"""Create access policy model.

Revision ID: 9c4f73699219
Revises: 9356ff164d89
Create Date: 2024-08-21 12:52:43.385380

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.access_policy import create_access_policy
from ldap_protocol.utils.queries import create_group, get_base_directories
from models import Directory, User

# revision identifiers, used by Alembic.
revision = "9c4f73699219"
down_revision = "9356ff164d89"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "AccessPolicies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("can_read", sa.Boolean(), nullable=False),
        sa.Column("can_add", sa.Boolean(), nullable=False),
        sa.Column("can_modify", sa.Boolean(), nullable=False),
        sa.Column("can_delete", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "AccessPolicyMemberships",
        sa.Column("dir_id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["dir_id"], ["Directory.id"]),
        sa.ForeignKeyConstraint(["policy_id"], ["AccessPolicies.id"]),
        sa.PrimaryKeyConstraint("dir_id", "policy_id"),
    )
    op.create_table(
        "GroupAccessPolicyMemberships",
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["Groups.id"]),
        sa.ForeignKeyConstraint(["policy_id"], ["AccessPolicies.id"]),
        sa.PrimaryKeyConstraint("group_id", "policy_id"),
    )

    async def _create_root_ap(connection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        await create_access_policy(
            name='Root Access Policy',
            can_add=True,
            can_modify=True,
            can_read=True,
            can_delete=True,
            grant_dn=base_dn_list[0].path_dn,
            groups=[
                "cn=domain admins,cn=groups," + base_dn_list[0].path_dn],
            session=session,
        )
        await session.flush()

        try:
            group_dir = await session.scalar(
                sa.select(Directory)
                .options(sa.orm.selectinload(Directory.group))
                .filter(Directory.name == 'domain users'))

            if not group_dir:
                _, group = await create_group(
                    'domain users', 513, session)
            else:
                group = group_dir.group

            for user in await session.scalars(
                    sa.select(User).options(sa.orm.selectinload(User.groups))):
                user.groups.append(group)

            await session.flush()
        except (IntegrityError, sa.exc.DBAPIError):
            pass

        await session.commit()
        await session.close()

    op.run_async(_create_root_ap)

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("GroupAccessPolicyMemberships")
    op.drop_table("AccessPolicyMemberships")
    op.drop_table("AccessPolicies")
    # ### end Alembic commands ###
