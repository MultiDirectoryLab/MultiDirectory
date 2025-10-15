"""Add Container objectClass to LDAP schema, is_system_user field.

Revision ID: f1abf7ef2443
Revises: 01f3f05a5b11
Create Date: 2025-10-10 06:23:58.238864

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Attribute, Directory
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision = "f1abf7ef2443"
down_revision = "01f3f05a5b11"
branch_labels: None | str = None
depends_on: None | str = None


def upgrade() -> None:
    """Upgrade."""

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

            if not directory or directory.object_class != "organizationalUnit":
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
    """Downgrade."""

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

            if not directory or directory.object_class != "container":
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

    op.drop_column("Users", "is_system_user")
