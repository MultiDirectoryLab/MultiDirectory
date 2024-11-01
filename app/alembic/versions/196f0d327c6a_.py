"""Add cascade.

Revision ID: 196f0d327c6a
Revises: 59e98bbd8ad8
Create Date: 2024-10-31 13:03:16.809350

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "196f0d327c6a"
down_revision = "59e98bbd8ad8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.drop_constraint(
        "AccessPolicyMemberships_policy_id_fkey",
        "AccessPolicyMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "AccessPolicyMemberships_dir_id_fkey",
        "AccessPolicyMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "AccessPolicyMemberships_policy_id_fkey",
        "AccessPolicyMemberships",
        "Directory",
        ["dir_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "AccessPolicyMemberships_dir_id_fkey",
        "AccessPolicyMemberships",
        "AccessPolicies",
        ["policy_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint(
        "DirectoryMemberships_directory_id_fkey",
        "DirectoryMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "DirectoryMemberships_group_id_fkey",
        "DirectoryMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "DirectoryMemberships_directory_id_fkey",
        "DirectoryMemberships",
        "Groups",
        ["group_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "DirectoryMemberships_group_id_fkey",
        "DirectoryMemberships",
        "Directory",
        ["directory_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint(
        "GroupAccessPolicyMemberships_policy_id_fkey",
        "GroupAccessPolicyMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "GroupAccessPolicyMemberships_group_id_fkey",
        "GroupAccessPolicyMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "GroupAccessPolicyMemberships_policy_id_fkey",
        "GroupAccessPolicyMemberships",
        "Groups",
        ["group_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "GroupAccessPolicyMemberships_group_id_fkey",
        "GroupAccessPolicyMemberships",
        "AccessPolicies",
        ["policy_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint(
        "PolicyMFAMemberships_policy_id_fkey",
        "PolicyMFAMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "PolicyMFAMemberships_group_id_fkey",
        "PolicyMFAMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "PolicyMFAMemberships_policy_id_fkey",
        "PolicyMFAMemberships",
        "Groups",
        ["group_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "PolicyMFAMemberships_group_id_fkey",
        "PolicyMFAMemberships",
        "Policies",
        ["policy_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint(
        "PolicyMemberships_group_id_fkey",
        "PolicyMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "PolicyMemberships_policy_id_fkey",
        "PolicyMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "PolicyMemberships_group_id_fkey",
        "PolicyMemberships",
        "Groups",
        ["group_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "PolicyMemberships_policy_id_fkey",
        "PolicyMemberships",
        "Policies",
        ["policy_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint(
        "Attributes_directoryId_fkey",
        "Attributes",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "Attributes_directoryId_fkey",
        "Attributes",
        "Directory",
        ["directoryId"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint(
        "Directory_parentId_fkey",
        "Directory",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "Directory_parentId_fkey",
        "Directory",
        "Directory",
        ["parentId"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint("Groups_directoryId_fkey", "Groups", type_="foreignkey")
    op.create_foreign_key(
        "Groups_directoryId_fkey",
        "Groups",
        "Directory",
        ["directoryId"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint("Users_directoryId_fkey", "Users", type_="foreignkey")
    op.create_foreign_key(
        "Users_directoryId_fkey",
        "Users",
        "Directory",
        ["directoryId"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_constraint(
        "PolicyMemberships_policy_id_fkey",
        "PolicyMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "PolicyMemberships_group_id_fkey",
        "PolicyMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "PolicyMemberships_policy_id_fkey",
        "PolicyMemberships",
        "Policies",
        ["policy_id"],
        ["id"],
    )
    op.create_foreign_key(
        "PolicyMemberships_group_id_fkey",
        "PolicyMemberships",
        "Groups",
        ["group_id"],
        ["id"],
    )

    op.drop_constraint(
        "PolicyMFAMemberships_group_id_fkey",
        "PolicyMFAMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "PolicyMFAMemberships_policy_id_fkey",
        "PolicyMFAMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "PolicyMFAMemberships_group_id_fkey",
        "PolicyMFAMemberships",
        "Groups",
        ["group_id"],
        ["id"],
    )
    op.create_foreign_key(
        "PolicyMFAMemberships_policy_id_fkey",
        "PolicyMFAMemberships",
        "Policies",
        ["policy_id"],
        ["id"],
    )

    op.drop_constraint(
        "GroupAccessPolicyMemberships_group_id_fkey",
        "GroupAccessPolicyMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "GroupAccessPolicyMemberships_policy_id_fkey",
        "GroupAccessPolicyMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "GroupAccessPolicyMemberships_group_id_fkey",
        "GroupAccessPolicyMemberships",
        "Groups",
        ["group_id"],
        ["id"],
    )
    op.create_foreign_key(
        "GroupAccessPolicyMemberships_policy_id_fkey",
        "GroupAccessPolicyMemberships",
        "AccessPolicies",
        ["policy_id"],
        ["id"],
    )

    op.drop_constraint(
        "DirectoryMemberships_group_id_fkey",
        "DirectoryMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "DirectoryMemberships_directory_id_fkey",
        "DirectoryMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "DirectoryMemberships_group_id_fkey",
        "DirectoryMemberships",
        "Groups",
        ["group_id"],
        ["id"],
    )
    op.create_foreign_key(
        "DirectoryMemberships_directory_id_fkey",
        "DirectoryMemberships",
        "Directory",
        ["directory_id"],
        ["id"],
    )

    op.drop_constraint(
        "AccessPolicyMemberships_policy_id_fkey",
        "AccessPolicyMemberships",
        type_="foreignkey",
    )
    op.drop_constraint(
        "AccessPolicyMemberships_dir_id_fkey",
        "AccessPolicyMemberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "AccessPolicyMemberships_dir_id_fkey",
        "AccessPolicyMemberships",
        "Directory",
        ["dir_id"],
        ["id"],
    )
    op.create_foreign_key(
        "AccessPolicyMemberships_policy_id_fkey",
        "AccessPolicyMemberships",
        "AccessPolicies",
        ["policy_id"],
        ["id"],
    )

    op.drop_constraint("Users_directoryId_fkey", "Users", type_="foreignkey")
    op.create_foreign_key(
        "Users_directoryId_fkey",
        "Users",
        "Directory",
        ["directoryId"],
        ["id"],
    )

    op.drop_constraint("Groups_directoryId_fkey", "Groups", type_="foreignkey")
    op.create_foreign_key(
        "Groups_directoryId_fkey",
        "Groups",
        "Directory",
        ["directoryId"],
        ["id"],
    )

    op.drop_constraint(
        "Directory_parentId_fkey",
        "Directory",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "Directory_parentId_fkey",
        "Directory",
        "Directory",
        ["parentId"],
        ["id"],
    )

    op.drop_constraint(
        "Attributes_directoryId_fkey",
        "Attributes",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "Attributes_directoryId_fkey",
        "Attributes",
        "Directory",
        ["directoryId"],
        ["id"],
    )
