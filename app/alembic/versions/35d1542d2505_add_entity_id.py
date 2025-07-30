"""Entity type id returned.

Revision ID: 35d1542d2505
Revises: fc8b7617c60a
Create Date: 2025-07-10 11:42:30.958798

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.sql import text

# revision identifiers, used by Alembic.
revision = "35d1542d2505"
down_revision = "fc8b7617c60a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.add_column(
        "EntityTypes",
        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
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
    op.drop_constraint("EntityTypes_pkey", "EntityTypes", type_="primary")

    op.create_primary_key("EntityTypes_pkey", "EntityTypes", ["id"])

    op.create_index(
        op.f("ix_EntityTypes_name"),
        "EntityTypes",
        ["name"],
        unique=True,
    )
    op.add_column(
        "Directory",
        sa.Column("entity_type_id", sa.Integer(), nullable=True),
    )
    op.create_index(
        op.f("ix_Directory_entity_type_id"),
        "Directory",
        ["entity_type_id"],
        unique=False,
    )
    op.create_foreign_key(
        "Directory_entity_type_id_fkey",
        "Directory",
        "EntityTypes",
        ["entity_type_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_index(
        op.f("ix_EntityTypes_object_class_names"),
        "EntityTypes",
        ["object_class_names"],
        unique=False,
    )

    op.execute(
        text("""
                UPDATE "Directory" d
                SET entity_type_id = et.id
                FROM "EntityTypes" et
                WHERE d.entity_type_name = et.name
            """),
    )

    op.drop_column("Directory", "entity_type_name")


def downgrade() -> None:
    """Downgrade."""
    op.add_column(
        "Directory",
        sa.Column("entity_type_name", sa.String(), nullable=True),
    )
    op.execute(
        text("""
                UPDATE "Directory" d
                SET entity_type_name = et.name
                FROM "EntityTypes" et
                WHERE d.entity_type_id = et.id
            """),
    )
    op.drop_constraint(
        "Directory_entity_type_id_fkey",
        "Directory",
        type_="foreignkey",
    )

    op.drop_column("Directory", "entity_type_id")

    op.drop_index(
        op.f("ix_EntityTypes_object_class_names"),
        table_name="EntityTypes",
    )
    op.drop_index(op.f("ix_EntityTypes_name"), table_name="EntityTypes")

    op.drop_constraint("EntityTypes_pkey", "EntityTypes", type_="primary")
    op.drop_column("EntityTypes", "id")
    op.create_primary_key("EntityTypes_pkey", "EntityTypes", ["name"])

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
