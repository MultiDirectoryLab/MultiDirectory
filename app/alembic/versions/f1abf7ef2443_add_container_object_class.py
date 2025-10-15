"""Add Container objectClass to LDAP schema, is_system_user field, and migrate ou= to cn=.

Revision ID: f1abf7ef2443
Revises: 01f3f05a5b11
Create Date: 2025-10-10 06:23:58.238864

"""

import logging

import sqlalchemy as sa
from alembic import op
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Attribute, Directory
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.raw_definition_parser import (
    RawDefinitionParser as RDParser,
)
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision = "f1abf7ef2443"
down_revision = "01f3f05a5b11"
branch_labels: None | str = None
depends_on: None | str = None


def upgrade() -> None:
    """Add Container objectClass to LDAP schema, is_system_user field, and migrate ou= to cn=."""

    async def _add_container_object_class(connection: AsyncConnection) -> None:
        """Add Container objectClass definition."""
        session = AsyncSession(bind=connection)
        await session.begin()

        container_raw_definition = (
            "( 2.5.6.6 NAME 'container' "
            "SUP top "
            "STRUCTURAL "
            "MUST cn "
            "MAY ( description $ displayName $ whenCreated $ whenChanged $ "
            "instanceType $ objectCategory $ objectClass $ "
            "distinguishedName $ "
            "objectGUID $ name $ showInAdvancedViewOnly $ systemFlags $ "
            "isCriticalSystemObject ) )"
        )

        object_class_dao = ObjectClassDAO(session)

        try:
            await object_class_dao.get("container")
            return
        except Exception as e:
            logging.info(f"Container objectClass not found, creating: {e}")

        object_class_info = RDParser.get_object_class_info(
            raw_definition=container_raw_definition,
        )

        object_class = await RDParser.create_object_class_by_info(
            session=session,
            object_class_info=object_class_info,
        )

        session.add(object_class)
        await session.commit()
        await session.close()

    async def _migrate_ou_to_cn_containers(
        connection: AsyncConnection,
    ) -> None:
        """Migrate existing ou= containers to cn= containers."""
        session = AsyncSession(bind=connection)
        await session.begin()

        containers_to_migrate = ["groups", "computers", "users"]

        for container_name in containers_to_migrate:
            directory = await session.scalar(
                select(Directory).where(qa(Directory.name) == container_name),
            )

            if not directory:
                continue

            if directory.object_class != "organizationalUnit":
                continue

            await session.execute(
                update(Directory)
                .where(qa(Directory.id) == directory.id)
                .values(object_class="container"),
            )

            rdn_attribute = await session.scalar(
                select(Attribute).where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == directory.rdname,
                ),
            )

            if rdn_attribute:
                await session.execute(
                    update(Attribute)
                    .where(qa(Attribute.id) == rdn_attribute.id)
                    .values(name="cn"),
                )

            object_class_attr = await session.scalar(
                select(Attribute).where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "objectClass",
                ),
            )

            if object_class_attr:
                await session.execute(
                    update(Attribute)
                    .where(qa(Attribute.id) == object_class_attr.id)
                    .values(value="container"),
                )

        await session.commit()

    op.run_async(_add_container_object_class)
    op.run_async(_migrate_ou_to_cn_containers)

    op.add_column(
        "Users",
        sa.Column(
            "is_system_user",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )


def downgrade() -> None:
    """Remove Container objectClass, is_system_user field, and migrate cn= back to ou=."""

    async def _remove_container_object_class(
        connection: AsyncConnection,
    ) -> None:
        """Remove Container objectClass definition (only if no containers exist)."""
        session = AsyncSession(bind=connection)
        await session.begin()

        container_count = await session.scalar(
            select(sa.func.count())
            .select_from(Directory)
            .where(qa(Directory.object_class) == "container"),
        )

        if container_count == 0:
            object_class_dao = ObjectClassDAO(session)
            try:
                await object_class_dao.delete("container")
                await session.commit()
            except Exception as e:
                logging.info(f"Could not delete container objectClass: {e}")
        else:
            logging.info(
                f"Skipping container objectClass deletion: {container_count} containers still exist",
            )

        await session.close()

    async def _migrate_cn_to_ou_containers(
        connection: AsyncConnection,
    ) -> None:
        """Migrate existing cn= containers back to ou= containers."""
        session = AsyncSession(bind=connection)
        await session.begin()

        containers_to_migrate = ["groups", "computers", "users"]

        for container_name in containers_to_migrate:
            directory = await session.scalar(
                select(Directory).where(qa(Directory.name) == container_name),
            )

            if not directory:
                continue

            if directory.object_class != "container":
                continue

            await session.execute(
                update(Directory)
                .where(qa(Directory.id) == directory.id)
                .values(object_class="organizationalUnit"),
            )

            rdn_attribute = await session.scalar(
                select(Attribute).where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == directory.rdname,
                ),
            )

            if rdn_attribute:
                await session.execute(
                    update(Attribute)
                    .where(qa(Attribute.id) == rdn_attribute.id)
                    .values(name="ou"),
                )

            object_class_attr = await session.scalar(
                select(Attribute).where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "objectClass",
                ),
            )

            if object_class_attr:
                await session.execute(
                    update(Attribute)
                    .where(qa(Attribute.id) == object_class_attr.id)
                    .values(value="organizationalUnit"),
                )

        await session.commit()

    op.run_async(_migrate_cn_to_ou_containers)
    op.run_async(_remove_container_object_class)

    op.drop_column("Users", "is_system_user")
