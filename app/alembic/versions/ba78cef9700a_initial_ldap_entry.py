"""Initial LDAP entry.

Revision ID: ba78cef9700a
Revises: 275222846605
Create Date: 2025-05-15 11:54:03.712099

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import exists, or_, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from extra.dev_data import ENTRY_DATAS
from ldap_protocol.ldap_schema.entry_crud import EntryDAO
from models import Attribute, Directory, User

# revision identifiers, used by Alembic.
revision = "ba78cef9700a"
down_revision = "275222846605"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema and data, creating LDAP entries."""
    op.create_table(
        "Entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "object_class_names",
            postgresql.ARRAY(sa.String()),
            nullable=False,
        ),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_Entries_name"),
        "Entries",
        ["name"],
        unique=True,
    )
    op.create_index(
        op.f("ix_Entries_object_class_names"),
        "Entries",
        ["object_class_names"],
        unique=True,
    )

    op.add_column(
        "Directory",
        sa.Column("entry_id", sa.Integer(), nullable=True),
    )
    op.create_index(
        op.f("ix_Directory_entry_id"),
        "Directory",
        ["entry_id"],
        unique=False,
    )
    op.create_foreign_key(
        "Directory_entry_id_fkey",
        "Directory",
        "Entries",
        ["entry_id"],
        ["id"],
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

    async def _create_entry(connection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        entry_manager = EntryDAO(session)

        for entry_data in ENTRY_DATAS:
            await entry_manager.create_entry(
                name=entry_data["name"],
                object_class_names=entry_data["object_class_names"],
                is_system=True,
            )

        await session.commit()

    op.run_async(_create_entry)

    async def _append_object_class_to_user_dir(connection) -> None:
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

    op.run_async(_append_object_class_to_user_dir)

    async def _attach_entry_to_directories(connection) -> None:
        session = AsyncSession(bind=connection)
        session.begin()
        entry_manager = EntryDAO(session)

        await entry_manager.attach_entry_to_directories()

        await session.commit()

    op.run_async(_attach_entry_to_directories)


def downgrade() -> None:
    """Downgrade database schema and data back to the previous state."""
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
        "Directory_entry_id_fkey",
        "Directory",
        type_="foreignkey",
    )
    op.drop_index(op.f("ix_Directory_entry_id"), table_name="Directory")
    op.drop_column("Directory", "entry_id")

    op.drop_index(op.f("ix_Entries_object_class_names"), table_name="Entries")
    op.drop_index(op.f("ix_Entries_name"), table_name="Entries")
    op.drop_table("Entries")
