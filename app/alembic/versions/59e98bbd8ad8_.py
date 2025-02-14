"""Initial.

Revision ID: 59e98bbd8ad8
Revises:
Create Date: 2024-10-28 08:57:53.115142

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "59e98bbd8ad8"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.create_table(
        "AccessPolicies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("can_read", sa.Boolean(), nullable=False),
        sa.Column("can_add", sa.Boolean(), nullable=False),
        sa.Column("can_modify", sa.Boolean(), nullable=False),
        sa.Column("can_delete", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "PasswordPolicies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "name",
            sa.String(length=255),
            server_default="Default Policy",
            nullable=False,
        ),
        sa.Column(
            "password_history_length",
            sa.Integer(),
            server_default="4",
            nullable=False,
        ),
        sa.Column(
            "maximum_password_age_days",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "minimum_password_age_days",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "minimum_password_length",
            sa.Integer(),
            server_default="7",
            nullable=False,
        ),
        sa.Column(
            "password_must_meet_complexity_requirements",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "Policies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column(
            "raw",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "netmasks",
            postgresql.ARRAY(postgresql.CIDR()),
            nullable=False,
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column(
            "mfa_status",
            sa.Enum("DISABLED", "ENABLED", "WHITELIST", name="mfaflags"),
            server_default="DISABLED",
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint(
            "priority",
            deferrable="True",
            initially="DEFERRED",
            name="priority_uc",
        ),
    )

    op.create_table(
        "Settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "Directory",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("parentId", sa.Integer(), nullable=True),
        sa.Column("objectClass", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column(
            "whenCreated",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("whenChanged", sa.DateTime(timezone=True), nullable=True),
        sa.Column("depth", sa.Integer(), nullable=True),
        sa.Column("objectSid", sa.String(), nullable=True),
        sa.Column("password_policy_id", sa.Integer(), nullable=True),
        sa.Column("objectGUID", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("path", postgresql.ARRAY(sa.String()), nullable=False),
        sa.ForeignKeyConstraint(
            ["parentId"],
            ["Directory.id"],
        ),
        sa.ForeignKeyConstraint(
            ["password_policy_id"],
            ["PasswordPolicies.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "parentId",
            "name",
            name="name_parent_uc",
            postgresql_nulls_not_distinct=True,
        ),
    )

    op.create_table(
        "AccessPolicyMemberships",
        sa.Column("dir_id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["dir_id"],
            ["Directory.id"],
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["AccessPolicies.id"],
        ),
        sa.PrimaryKeyConstraint("dir_id", "policy_id"),
    )
    op.create_table(
        "Attributes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=True),
        sa.Column("bvalue", sa.LargeBinary(), nullable=True),
        sa.Column("directoryId", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "(value IS NULL) <> (bvalue IS NULL)",
            name="constraint_value_xor_bvalue",
        ),
        sa.ForeignKeyConstraint(
            ["directoryId"],
            ["Directory.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "Groups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("directoryId", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["directoryId"],
            ["Directory.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "Users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("sAMAccountName", sa.String(), nullable=False),
        sa.Column("userPrincipalName", sa.String(), nullable=False),
        sa.Column("mail", sa.String(length=255), nullable=True),
        sa.Column("displayName", sa.String(), nullable=True),
        sa.Column("password", sa.String(), nullable=True),
        sa.Column("lastLogon", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accountExpires", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "password_history",
            postgresql.ARRAY(sa.String()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("directoryId", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["directoryId"],
            ["Directory.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sAMAccountName"),
        sa.UniqueConstraint("userPrincipalName"),
    )
    op.create_table(
        "DirectoryMemberships",
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("directory_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["directory_id"],
            ["Directory.id"],
        ),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["Groups.id"],
        ),
        sa.PrimaryKeyConstraint("group_id", "directory_id"),
    )
    op.create_table(
        "GroupAccessPolicyMemberships",
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["Groups.id"],
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["AccessPolicies.id"],
        ),
        sa.PrimaryKeyConstraint("group_id", "policy_id"),
    )
    op.create_table(
        "PolicyMFAMemberships",
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["Groups.id"],
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["Policies.id"],
        ),
        sa.PrimaryKeyConstraint("group_id", "policy_id"),
    )
    op.create_table(
        "PolicyMemberships",
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["Groups.id"],
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["Policies.id"],
        ),
        sa.PrimaryKeyConstraint("group_id", "policy_id"),
    )

    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')

    op.create_index(
        op.f("ix_Policies_netmasks"),
        "Policies",
        ["netmasks"],
        unique=True,
    )
    op.create_index(
        op.f("ix_Settings_name"),
        "Settings",
        ["name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_Directory_parentId"),
        "Directory",
        ["parentId"],
        unique=False,
    )
    op.create_index(
        op.f("ix_Directory_path"),
        "Directory",
        ["path"],
        unique=False,
    )
    op.create_index(
        op.f("ix_Attributes_name"),
        "Attributes",
        ["name"],
        unique=False,
    )

    op.create_index("ix_directory_objectGUID", "Directory", ["objectGUID"])

    op.execute(
        sa.text("""
    CREATE OR REPLACE FUNCTION array_lowercase(varchar[]) RETURNS varchar[] AS
    $BODY$
    SELECT array_agg(q.tag) FROM (
        SELECT btrim(lower(unnest($1)))::varchar AS tag
    ) AS q;
    $BODY$
    language sql IMMUTABLE;"""),
    )
    op.execute(
        sa.text(
            """
            CREATE INDEX lw_path
            ON "Directory" USING GIN(array_lowercase("path"));
            """,
        ),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_index("ix_directory_objectGUID", table_name="Directory")
    op.drop_index(op.f("ix_Directory_path"), table_name="Directory")
    op.drop_index("lw_path", table_name="Directory")
    op.drop_index(op.f("ix_Attributes_name"), table_name="Attributes")
    op.drop_index(op.f("ix_Settings_name"), table_name="Settings")
    op.drop_index(op.f("ix_Policies_netmasks"), table_name="Policies")
    op.drop_index(op.f("ix_Directory_parentId"), table_name="Directory")

    op.drop_table("PolicyMemberships")
    op.drop_table("PolicyMFAMemberships")
    op.drop_table("GroupAccessPolicyMemberships")
    op.drop_table("DirectoryMemberships")
    op.drop_table("Users")
    op.drop_table("Groups")
    op.drop_table("Attributes")
    op.drop_table("AccessPolicyMemberships")
    op.drop_table("Directory")
    op.drop_table("Settings")
    op.drop_table("Policies")
    op.drop_table("PasswordPolicies")
    op.drop_table("AccessPolicies")

    op.execute(sa.text("DROP TYPE mfaflags"))
    op.execute(sa.text("DROP FUNCTION array_lowercase;"))
