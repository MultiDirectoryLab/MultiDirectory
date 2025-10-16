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
        directories = await session.scalars(
            select(Directory).where(
                qa(Directory.name).in_(containers_to_migrate),
                qa(Directory.object_class) == "organizationalUnit",
            ),
        )

        for directory in directories:
            await session.execute(
                update(Directory)
                .where(qa(Directory.id) == directory.id)
                .values(object_class="container"),
            )

            await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == directory.rdname,
                )
                .values(name="cn"),
            )

            await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "objectClass",
                )
                .values(value="container"),
            )

            new_path = []
            for path_component in directory.path:
                if path_component.startswith("ou="):
                    name = path_component.split("=", 1)[1]
                    new_path.append(f"cn={name}")
                else:
                    new_path.append(path_component)

            await session.execute(
                update(Directory)
                .where(qa(Directory.id) == directory.id)
                .values(path=new_path),
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
        directories = await session.scalars(
            select(Directory).where(
                qa(Directory.name).in_(containers_to_migrate),
                qa(Directory.object_class) == "container",
            ),
        )
        for directory in directories:
            await session.execute(
                update(Directory)
                .where(qa(Directory.id) == directory.id)
                .values(object_class="organizationalUnit"),
            )

            await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == directory.rdname,
                )
                .values(name="ou"),
            )

            await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "objectClass",
                )
                .values(value="organizationalUnit"),
            )

            new_path = []
            for path_component in directory.path:
                if path_component.startswith("cn="):
                    name = path_component.split("=", 1)[1]
                    new_path.append(f"ou={name}")
                else:
                    new_path.append(path_component)

            await session.execute(
                update(Directory)
                .where(qa(Directory.id) == directory.id)
                .values(path=new_path),
            )

        await session.commit()

    op.run_async(_migrate_cn_to_ou_containers)

    op.drop_column("Users", "is_system_user")
