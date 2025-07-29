"""index_single_level.

Revision ID: a7971f00ba4d
Revises: 35d1542d2505
Create Date: 2025-07-22 11:13:48.397808

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a7971f00ba4d"
down_revision = "35d1542d2505"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create index for Directory depth field."""
    op.execute(
        sa.text(
            'CREATE INDEX "idx_User_san_gin" '
            'ON "Users" USING gin ("sAMAccountName" gin_trgm_ops);'
        )
    )
    op.execute(
        sa.text(
            'CREATE INDEX "idx_User_upn_gin" '
            'ON "Users" USING gin ("userPrincipalName" gin_trgm_ops);'
        )
    )
    op.execute(
        sa.text(
            'CREATE INDEX "idx_User_display_name_gin" '
            'ON "Users" USING gin ("displayName" gin_trgm_ops);'
        )
    )
    op.execute(
        sa.text(
            'CREATE INDEX "idx_user_hash_dir_id" '
            'ON "Users" USING hash ("directoryId");'
        )
    )
    op.execute(
        sa.text(
            """
            CREATE INDEX lw_object_class_names
            ON "EntityTypes" USING GIN(array_lowercase("object_class_names"));
            """,
        ),
    )
    op.execute(
        sa.text(
            'CREATE INDEX "idx_entity_type_dir_id" '
            'ON "Directory" USING hash ("entity_type_id");'
        )
    )
    op.execute(
        sa.text(
            'CREATE INDEX "idx_group_dir_id" '
            'ON "Groups" USING hash ("directoryId");'
        )
    )
    op.execute(
        sa.text(
            'CREATE INDEX "idx_Directory_depth_hash" '
            'ON "Directory" '
            "USING hash (depth);"
        )
    )
    op.execute(
        sa.text(
            'CREATE INDEX "idx_composite_attributes_directory_id_name" '
            'ON "Attributes" ("directoryId", lower("name"));'
        )
    )
    op.execute(
        sa.text(
            'CREATE INDEX "idx_attributes_value" '
            'ON "Attributes" USING gin ("value" gin_trgm_ops);'
        )
    )
    op.execute(
        sa.text(
            'CREATE INDEX "idx_attributes_name_value_trgm" '
            'ON "Attributes" USING gin '
            '("name" gin_trgm_ops, "value" gin_trgm_ops);'
        )
    )


def downgrade() -> None:
    """Remove indexes for Directory depth field and Attributes table."""
    op.drop_index("idx_User_san_gin", "Users")
    op.drop_index("idx_User_upn_gin", "Users")
    op.drop_index("idx_User_display_name_gin", "Users")
    op.drop_index("idx_user_hash_dir_id", "Users")
    op.drop_index("lw_object_class_names", "EntityTypes")
    op.drop_index("idx_entity_type_dir_id", "Directory")
    op.drop_index("idx_group_dir_id", "Groups")
    op.drop_index("idx_Directory_depth_hash", "Directory")
    op.drop_index("idx_composite_attributes_directory_id_name", "Attributes")
    op.drop_index("idx_attributes_value", "Attributes")
    op.drop_index("idx_attributes_name_value_trgm", "Attributes")
