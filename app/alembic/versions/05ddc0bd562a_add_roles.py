"""Add roles.

Revision ID: 05ddc0bd562a
Revises: 35d1542d2505
Create Date: 2025-07-17 09:16:20.056149
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "05ddc0bd562a"
down_revision = "35d1542d2505"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.create_table(
        "Roles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("creator_upn", sa.String(), nullable=True),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.Column(
            "whenCreated",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "AccessControlEntries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("roleId", sa.Integer(), nullable=False),
        sa.Column("ace_type", sa.SMALLINT(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("scope", sa.SMALLINT(), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("attributeTypeId", sa.Integer(), nullable=True),
        sa.Column("entityTypeId", sa.Integer(), nullable=True),
        sa.Column("is_allow", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["attributeTypeId"], ["AttributeTypes.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["entityTypeId"], ["EntityTypes.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["roleId"], ["Roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_AccessControlEntries_ace_type"),
        "AccessControlEntries",
        ["ace_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_AccessControlEntries_scope"),
        "AccessControlEntries",
        ["scope"],
        unique=False,
    )
    op.create_table(
        "AccessControlEntryDirectoryMemberships",
        sa.Column("access_control_entry_id", sa.Integer(), nullable=False),
        sa.Column("directory_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["access_control_entry_id"],
            ["AccessControlEntries.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["directory_id"], ["Directory.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("access_control_entry_id", "directory_id"),
    )
    op.create_table(
        "GroupRoleMemberships",
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"], ["Groups.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["role_id"], ["Roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("group_id", "role_id"),
    )
    op.drop_table("GroupAccessPolicyMemberships")
    op.drop_table("AccessPolicyMemberships")
    op.drop_table("AccessPolicies")


def downgrade() -> None:
    """Downgrade."""
    op.create_table(
        "AccessPolicies",
        sa.Column(
            "id",
            sa.INTEGER(),
            server_default=sa.text(
                "nextval('\"AccessPolicies_id_seq\"'::regclass)"
            ),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "name", sa.VARCHAR(length=255), autoincrement=False, nullable=False
        ),
        sa.Column(
            "can_read", sa.BOOLEAN(), autoincrement=False, nullable=False
        ),
        sa.Column(
            "can_add", sa.BOOLEAN(), autoincrement=False, nullable=False
        ),
        sa.Column(
            "can_modify", sa.BOOLEAN(), autoincrement=False, nullable=False
        ),
        sa.Column(
            "can_delete", sa.BOOLEAN(), autoincrement=False, nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="AccessPolicies_pkey"),
        sa.UniqueConstraint(
            "name",
            name="AccessPolicies_name_key",
            postgresql_include=[],
            postgresql_nulls_not_distinct=False,
        ),
        postgresql_ignore_search_path=False,
    )
    op.create_table(
        "AccessPolicyMemberships",
        sa.Column("dir_id", sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column(
            "policy_id", sa.INTEGER(), autoincrement=False, nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["dir_id"],
            ["Directory.id"],
            name=op.f("AccessPolicyMemberships_policy_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["AccessPolicies.id"],
            name=op.f("AccessPolicyMemberships_dir_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "dir_id", "policy_id", name=op.f("AccessPolicyMemberships_pkey")
        ),
    )
    op.create_table(
        "GroupAccessPolicyMemberships",
        sa.Column(
            "group_id", sa.INTEGER(), autoincrement=False, nullable=False
        ),
        sa.Column(
            "policy_id", sa.INTEGER(), autoincrement=False, nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["Groups.id"],
            name=op.f("GroupAccessPolicyMemberships_policy_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["AccessPolicies.id"],
            name=op.f("GroupAccessPolicyMemberships_group_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "group_id",
            "policy_id",
            name=op.f("GroupAccessPolicyMemberships_pkey"),
        ),
        sa.UniqueConstraint(
            "group_id",
            "policy_id",
            name=op.f("group_policy_uc"),
            postgresql_include=[],
            postgresql_nulls_not_distinct=False,
        ),
    )
    op.drop_table("GroupRoleMemberships")
    op.drop_table("AccessControlEntryDirectoryMemberships")
    op.drop_index(
        op.f("ix_AccessControlEntries_scope"),
        table_name="AccessControlEntries",
    )
    op.drop_index(
        op.f("ix_AccessControlEntries_ace_type"),
        table_name="AccessControlEntries",
    )
    op.drop_table("AccessControlEntries")
    op.drop_table("Roles")
