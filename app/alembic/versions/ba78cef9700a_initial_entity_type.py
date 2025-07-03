"""Initial Entity Type.

Revision ID: ba78cef9700a
Revises: 275222846605
Create Date: 2025-05-15 11:54:03.712099

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import exists, or_, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from extra.dev_data import ENTITY_TYPE_DATAS
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from models import Attribute, Directory, User

# revision identifiers, used by Alembic.
revision = "ba78cef9700a"
down_revision = "275222846605"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema and data, creating Entity Types."""
    op.create_table(
        "EntityTypes",
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "object_class_names",
            postgresql.ARRAY(sa.String()),
            nullable=False,
        ),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_index(
        "idx_entity_types_name_gin_trgm",
        "EntityTypes",
        [sa.literal_column("name gin_trgm_ops")],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )
    op.create_index(
        op.f("ix_Entity_Type_object_class_names"),
        "EntityTypes",
        ["object_class_names"],
        unique=True,
    )

    op.add_column(
        "Directory",
        sa.Column("entity_type_name", sa.String(length=255), nullable=True),
    )
    op.create_index(
        op.f("ix_Directory_entity_type_name"),
        "Directory",
        ["entity_type_name"],
        unique=False,
    )
    op.create_foreign_key(
        "Directory_entity_type_name_fkey",
        "Directory",
        "EntityTypes",
        ["entity_type_name"],
        ["name"],
        ondelete="SET NULL",
    )

    op.drop_index("ix_AttributeTypes_oid", table_name="AttributeTypes")
    op.create_unique_constraint(
        "AttributeTypes_oid_uc",
        "AttributeTypes",
        ["oid"],
    )

    op.drop_index("ix_ObjectClasses_oid", table_name="ObjectClasses")
    op.create_unique_constraint(
        "ObjectClasses_oid_uc",
        "ObjectClasses",
        ["oid"],
    )

    async def _create_entity_types(connection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        attribute_type_dao = AttributeTypeDAO(session)
        object_class_dao = ObjectClassDAO(
            session,
            attribute_type_dao=attribute_type_dao,
        )
        entity_type_dao = EntityTypeDAO(
            session,
            object_class_dao=object_class_dao,
        )

        for entity_type_data in ENTITY_TYPE_DATAS:
            await entity_type_dao.create_one(
                name=entity_type_data["name"],
                object_class_names=entity_type_data["object_class_names"],
                is_system=True,
            )

        await session.commit()

    op.run_async(_create_entity_types)

    async def _append_object_class_to_user_dirs(connection) -> None:
        session = AsyncSession(bind=connection)
        session.begin()

        query = (
            select(User)
            .join(Directory)
            .where(
                ~exists(
                    select(Attribute.id)
                    .where(
                        Attribute.directory_id == Directory.id,
                        or_(
                            Attribute.name == "objectClass",
                            Attribute.name == "objectclass",
                        ),
                        Attribute.value == "inetOrgPerson",
                    )
                ),
            )
        )  # fmt: skip

        for user in await session.scalars(query):
            session.add(
                Attribute(
                    directory=user.directory,
                    name="objectClass",
                    value="inetOrgPerson",
                )
            )

        await session.commit()

    op.run_async(_append_object_class_to_user_dirs)

    async def _attach_entity_type_to_directories(connection) -> None:
        session = AsyncSession(bind=connection)
        session.begin()
        attribute_type_dao = AttributeTypeDAO(session)
        object_class_dao = ObjectClassDAO(
            session,
            attribute_type_dao=attribute_type_dao,
        )
        entity_type_dao = EntityTypeDAO(
            session,
            object_class_dao=object_class_dao,
        )

        await entity_type_dao.attach_entity_type_to_directories()

        await session.commit()

    op.run_async(_attach_entity_type_to_directories)


def downgrade() -> None:
    """Downgrade database schema and data back to the previous state."""
    op.drop_index(
        "idx_entity_types_name_gin_trgm",
        table_name="EntityTypes",
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )
    op.drop_constraint("ObjectClasses_oid_uc", "ObjectClasses", type_="unique")
    op.create_index(
        "ix_ObjectClasses_oid",
        "ObjectClasses",
        ["oid"],
        unique=True,
    )

    op.drop_constraint(
        "AttributeTypes_oid_uc",
        "AttributeTypes",
        type_="unique",
    )
    op.create_index(
        "ix_AttributeTypes_oid",
        "AttributeTypes",
        ["oid"],
        unique=True,
    )

    op.drop_constraint(
        "Directory_entity_type_name_fkey",
        "Directory",
        type_="foreignkey",
    )
    op.drop_index(
        op.f("ix_Directory_entity_type_name"),
        table_name="Directory",
    )
    op.drop_column("Directory", "entity_type_name")

    op.drop_index(
        op.f("ix_Entity_Type_object_class_names"), table_name="EntityTypes"
    )
    op.drop_table("EntityTypes")
