"""Add primaryGroupId attribute and domain computers group.

Revision ID: 01f3f05a5b11
Revises: eeaed5989eb0
Create Date: 2025-09-26 12:36:05.974255

"""

from alembic import op
from sqlalchemy import delete, exists, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, selectinload

from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.role_dao import RoleDAO
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.queries import (
    create_group,
    get_base_directories,
    get_filter_from_path,
    get_search_path,
)
from models import Attribute, Directory, EntityType, Group

# revision identifiers, used by Alembic.
revision = "01f3f05a5b11"
down_revision = "eeaed5989eb0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""

    async def _add_domain_computers_group(connection) -> None:
        session = AsyncSession(connection)
        await session.begin()

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        object_class_dao = ObjectClassDAO(session)
        entity_type_dao = EntityTypeDAO(
            session,
            object_class_dao=object_class_dao,
        )
        role_dao = RoleDAO(session)
        ace_dao = AccessControlEntryDAO(session)
        role_use_case = RoleUseCase(role_dao, ace_dao)

        try:
            group_dir_query = select(
                exists(Directory).where(Directory.name == "domain computers"),
            )
            group_dir = (await session.scalars(group_dir_query)).one()

            if group_dir:
                return

            dir_, group_ = await create_group(
                name="domain computers",
                sid=515,
                session=session,
            )

            await session.flush()

            computer_entity_type = await entity_type_dao.get("Computer")
            computer_dirs = await session.scalars(
                select(Directory).where(
                    Directory.entity_type_id == computer_entity_type.id,
                ),
            )
            await session.refresh(
                group_,
                attribute_names=["members"],
                with_for_update=None,
            )
            group_.members.extend(computer_dirs.all())

            query = (
                select(Directory)
                .options(
                    selectinload(Directory.attributes),
                )
                .filter(
                    get_filter_from_path(
                        "cn=groups," + base_dn_list[0].path_dn,
                    ),
                )
            )

            parent = (await session.scalars(query)).one()

            await session.refresh(
                instance=dir_,
                attribute_names=["attributes"],
                with_for_update=None,
            )
            await entity_type_dao.attach_entity_type_to_directory(dir_, False)
            await role_use_case.inherit_parent_aces(
                parent_directory=parent,
                directory=dir_,
            )
            await session.flush()
        except (IntegrityError, DBAPIError):
            pass

        await session.commit()
        await session.close()

    op.run_async(_add_domain_computers_group)

    async def _add_primary_group_id(connection) -> None:
        session = AsyncSession(connection)
        await session.begin()

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        entity_type = await session.scalars(
            select(EntityType.id)
            .where(EntityType.name.in_(["User", "Computer"])),
        )  # fmt: skip

        entity_type_ids = list(entity_type.all())

        query = (
            select(Directory)
            .options(
                selectinload(Directory.groups).selectinload(Group.directory),
            )
            .where(
                Directory.entity_type_id.in_(entity_type_ids),
            )
        )

        result = await session.execute(query)
        directories = result.scalars().all()
        for directory in directories:
            for group in directory.groups:
                session.add(
                    Attribute(
                        name="primaryGroupID",
                        value=group.directory.relative_id,
                        directory=directory,
                    ),
                )
                break

        await session.commit()

    op.run_async(_add_primary_group_id)


def downgrade() -> None:
    """Downgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    async def _delete_domain_computers_group(connection) -> None:
        session = AsyncSession(connection)
        await session.begin()

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        group_dn = "cn=domain computers,cn=groups," + base_dn_list[0].path_dn

        await session.execute(
            delete(Directory)
            .where(Directory.path == get_search_path(group_dn)),
        )  # fmt: skip

        await session.commit()

    op.run_async(_delete_domain_computers_group)

    session.execute(
        delete(Attribute).where(Attribute.name == "primaryGroupID"),
    )
    session.commit()
