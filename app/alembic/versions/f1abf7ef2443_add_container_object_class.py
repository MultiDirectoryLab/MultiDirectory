"""Add Container objectClass to LDAP schema field.

Revision ID: f1abf7ef2443
Revises: 01f3f05a5b11
Create Date: 2025-10-10 06:23:58.238864

"""

from alembic import op
from sqlalchemy import func, select, update
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
                .values(object_class="container", rdname="cn"),
            )

            await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "ou",
                )
                .values(name="cn"),
            )

            await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "objectClass",
                    qa(Attribute.value) == "organizationalUnit",
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

        for container_name in containers_to_migrate:
            await session.execute(
                update(Directory)
                .where(
                    func.array_position(
                        qa(Directory.path),
                        f"ou={container_name}",
                    ).isnot(None),
                )
                .values(
                    path=func.array_replace(
                        qa(Directory.path),
                        f"ou={container_name}",
                        f"cn={container_name}",
                    ),
                ),
            )

        await session.commit()

    op.run_async(_migrate_ou_to_cn_containers)


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
                    qa(Attribute.name) == "cn",
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

        for container_name in containers_to_migrate:
            await session.execute(
                update(Directory)
                .where(
                    func.array_position(
                        qa(Directory.path),
                        f"cn={container_name}",
                    ).isnot(None),
                )
                .values(
                    path=func.array_replace(
                        qa(Directory.path),
                        f"cn={container_name}",
                        f"ou={container_name}",
                    ),
                ),
            )

        await session.commit()

    op.run_async(_migrate_cn_to_ou_containers)
