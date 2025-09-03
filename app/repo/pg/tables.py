"""MultiDirectory LDAP tables.

(imperative mapping + dataclasses, SQLAlchemy 2.0).
"""

from __future__ import annotations

import uuid
from typing import Literal, TypeVar, cast

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    asc,
    desc,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, JSON, UUID as PG_UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import QueryableAttribute, registry, relationship, synonym
from sqlalchemy.sql import expression
from sqlalchemy.sql.compiler import DDLCompiler

from entities import (
    AccessControlEntry,
    Attribute,
    AttributeType,
    AuditDestination,
    AuditPolicy,
    AuditPolicyTrigger,
    CatalogueSetting,
    Directory,
    EntityType,
    Group,
    NetworkPolicy,
    ObjectClass,
    PasswordPolicy,
    Role,
    User,
)
from enums import (
    AceType,
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
    AuditSeverity,
    KindType,
    MFAFlags,
    RoleScope,
)

type DistinguishedNamePrefix = Literal["cn", "ou", "dc"]
UniqueConstraint.argument_for("postgresql", "nulls_not_distinct", None)


_T = TypeVar("_T")


def queryable_attr(value: _T) -> QueryableAttribute[_T]:
    """Cast a value to a QueryableAttribute.

    :param T value: The value to cast.
    :return QueryableAttribute[T]: The casted value.
    """
    return cast("QueryableAttribute[_T]", value)


@compiles(UniqueConstraint, "postgresql")
def _compile_create_uc(
    create: UniqueConstraint,
    compiler: DDLCompiler,
    **kw: dict,
) -> str:
    stmt = compiler.visit_unique_constraint(create, **kw)
    postgresql_opts = create.dialect_options["postgresql"]
    if postgresql_opts.get("nulls_not_distinct"):
        return stmt.rstrip().replace("UNIQUE (", "UNIQUE NULLS NOT DISTINCT (")
    return stmt


mapper_registry = registry()
metadata: MetaData = mapper_registry.metadata

true_ = expression.true()
false_ = expression.false()


settings_table = Table(
    "Settings",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("value", String, nullable=False),
    Index("ix_Settings_name", "name", unique=True),
)

directory_table = Table(
    "Directory",
    metadata,
    Column("id", Integer, primary_key=True),
    Column(
        "parentId",
        Integer,
        ForeignKey("Directory.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
        key="parent_id",
    ),
    Column(
        "entity_type_id",
        Integer,
        ForeignKey("EntityTypes.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    ),
    Column("objectClass", String, nullable=False, key="object_class"),
    Column("name", String, nullable=False),
    Column("rdname", String(64), nullable=False),
    Column(
        "whenCreated",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        key="created_at",
    ),
    Column(
        "whenChanged",
        DateTime(timezone=True),
        onupdate=func.now(),
        nullable=True,
        key="updated_at",
    ),
    Column("depth", Integer, nullable=True),
    Column("objectSid", String, nullable=True, key="object_sid"),
    Column(
        "password_policy_id",
        Integer,
        ForeignKey("PasswordPolicies.id"),
        nullable=True,
    ),
    Column(
        "objectGUID",
        PG_UUID(as_uuid=True),
        default=uuid.uuid4,
        nullable=False,
        key="object_guid",
    ),
    Column("path", ARRAY(String), nullable=False, index=True),
    UniqueConstraint(
        "parent_id",
        "name",
        name="name_parent_uc",
        postgresql_nulls_not_distinct=True,
    ),
    Index("idx_Directory_depth_hash", "depth", postgresql_using="hash"),
    Index("idx_entity_type_dir_id", "entity_type_id", postgresql_using="hash"),
    Index("ix_directory_objectGUID", "object_guid", postgresql_using="hash"),
    Index("lw_path", text("array_lowercase(path)"), postgresql_using="gin"),
)

groups_table = Table(
    "Groups",
    metadata,
    Column("id", Integer, primary_key=True),
    Column(
        "directoryId",
        Integer,
        ForeignKey("Directory.id", ondelete="CASCADE"),
        nullable=False,
        key="directory_id",
    ),
    Index("idx_group_dir_id", "directory_id", postgresql_using="hash"),
)

users_table = Table(
    "Users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column(
        "directoryId",
        Integer,
        ForeignKey("Directory.id", ondelete="CASCADE"),
        nullable=False,
        key="directory_id",
    ),
    Column(
        "sAMAccountName",
        String,
        nullable=False,
        unique=True,
        key="sam_account_name",
    ),
    Column(
        "userPrincipalName",
        String,
        nullable=False,
        unique=True,
        key="user_principal_name",
    ),
    Column("mail", String(255), key="mail"),
    Column("displayName", String, nullable=True, key="display_name"),
    Column("password", String, nullable=True, key="password"),
    Column("lastLogon", DateTime(timezone=True), key="last_logon"),
    Column("accountExpires", DateTime(timezone=True), key="account_exp"),
    Column(
        "password_history",
        ARRAY(String),
        server_default="{}",
        nullable=False,
    ),
    Index("idx_User_display_name_gin", "display_name", postgresql_using="gin"),
    Index("idx_User_san_gin", "sam_account_name", postgresql_using="gin"),
    Index("idx_User_upn_gin", "user_principal_name", postgresql_using="gin"),
    Index("idx_user_hash_dir_id", "directory_id", postgresql_using="hash"),
)

directory_memberships_table = Table(
    "DirectoryMemberships",
    metadata,
    Column(
        "group_id",
        Integer,
        ForeignKey("Groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "directory_id",
        Integer,
        ForeignKey("Directory.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

policy_memberships_table = Table(
    "PolicyMemberships",
    metadata,
    Column(
        "group_id",
        Integer,
        ForeignKey("Groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "policy_id",
        Integer,
        ForeignKey("Policies.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

policy_mfa_memberships_table = Table(
    "PolicyMFAMemberships",
    metadata,
    Column(
        "group_id",
        Integer,
        ForeignKey("Groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "policy_id",
        Integer,
        ForeignKey("Policies.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

group_role_memberships_table = Table(
    "GroupRoleMemberships",
    metadata,
    Column(
        "group_id",
        Integer,
        ForeignKey("Groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "role_id",
        Integer,
        ForeignKey("Roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

entity_types_table = Table(
    "EntityTypes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False, unique=True, index=True),
    Column("object_class_names", ARRAY(String), index=True),
    Column("is_system", Boolean, nullable=False),
    Index("idx_entity_types_name_gin_trgm", "name", postgresql_using="gin"),
    Index(
        "ix_Entity_Type_object_class_names",
        "object_class_names",
        unique=True,
    ),
    Index(
        "lw_object_class_names",
        text("array_lowercase(object_class_names)"),
        postgresql_using="gin",
    ),
)

attribute_types_table = Table(
    "AttributeTypes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("oid", String(255), nullable=False, unique=True),
    Column("name", String(255), nullable=False, unique=True, index=True),
    Column("syntax", String(255), nullable=False),
    Column("single_value", Boolean, nullable=False),
    Column("no_user_modification", Boolean, nullable=False),
    Column("is_system", Boolean, nullable=False),
    Index("idx_attribute_types_name_gin_trgm", "name", postgresql_using="gin"),
)

object_classes_table = Table(
    "ObjectClasses",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("oid", String(255), nullable=False, unique=True),
    Column("name", String(255), nullable=False, unique=True),
    Column(
        "superior_name",
        String(255),
        ForeignKey("ObjectClasses.name", ondelete="SET NULL"),
        nullable=True,
    ),
    Column("kind", Enum(KindType, name="objectclasskinds"), nullable=False),
    Column("is_system", Boolean, nullable=False),
    Index("idx_object_classes_name_gin_trgm", "name", postgresql_using="gin"),
    Index("ix_ObjectClasses_name", "name", unique=True),
)

object_class_attr_must_table = Table(
    "ObjectClassAttributeTypeMustMemberships",
    metadata,
    Column(
        "attribute_type_name",
        String(255),
        ForeignKey("AttributeTypes.name", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "object_class_name",
        String(255),
        ForeignKey("ObjectClasses.name", ondelete="CASCADE"),
        primary_key=True,
    ),
    UniqueConstraint(
        "attribute_type_name",
        "object_class_name",
        name="object_class_must_attribute_type_uc",
    ),
)

object_class_attr_may_table = Table(
    "ObjectClassAttributeTypeMayMemberships",
    metadata,
    Column(
        "attribute_type_name",
        String(255),
        ForeignKey("AttributeTypes.name", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "object_class_name",
        String(255),
        ForeignKey("ObjectClasses.name", ondelete="CASCADE"),
        primary_key=True,
    ),
    UniqueConstraint(
        "attribute_type_name",
        "object_class_name",
        name="object_class_may_attribute_type_uc",
    ),
)

attributes_table = Table(
    "Attributes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column(
        "directoryId",
        Integer,
        ForeignKey("Directory.id", ondelete="CASCADE"),
        nullable=False,
        key="directory_id",
    ),
    Column("name", String, nullable=False, index=True),
    Column("value", String),
    Column("bvalue", LargeBinary),
    CheckConstraint(
        "(value IS NULL) <> (bvalue IS NULL)",
        name="constraint_value_xor_bvalue",
    ),
    Index("idx_attributes_name_gin_trgm", "name", postgresql_using="gin"),
    Index(
        "idx_attributes_lw_name_btree",
        text("lower(name::text)"),
        postgresql_using="btree",
    ),
    Index(
        "idx_composite_attributes_directory_id_name",
        "directory_id",
        text("lower(name::text)"),
        postgresql_using="btree",
    ),
    Index("idx_attributes_value", "value", postgresql_using="gin"),
    Index(
        "idx_attributes_name_value_trgm",
        "name",
        "value",
        postgresql_using="gin",
    ),
)

password_policies_table = Table(
    "PasswordPolicies",
    metadata,
    Column("id", Integer, primary_key=True),
    Column(
        "name",
        String(255),
        nullable=False,
        unique=True,
        server_default="Default Policy",
    ),
    Column(
        "password_history_length",
        Integer,
        nullable=False,
        server_default="4",
    ),
    Column(
        "maximum_password_age_days",
        Integer,
        nullable=False,
        server_default="0",
    ),
    Column(
        "minimum_password_age_days",
        Integer,
        nullable=False,
        server_default="0",
    ),
    Column(
        "minimum_password_length",
        Integer,
        nullable=False,
        server_default="7",
    ),
    Column(
        "password_must_meet_complexity_requirements",
        Boolean,
        server_default=false_,
        nullable=False,
    ),
)

roles_table = Table(
    "Roles",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False, unique=True),
    Column("creator_upn", String, nullable=True),
    Column("is_system", Boolean, nullable=False),
    Column(
        "whenCreated",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        key="created_at",
    ),
)

access_control_entries_table = Table(
    "AccessControlEntries",
    metadata,
    Column("id", Integer, primary_key=True),
    Column(
        "roleId",
        Integer,
        ForeignKey("Roles.id", ondelete="CASCADE"),
        nullable=False,
        key="role_id",
    ),
    Column("ace_type", Enum(AceType), nullable=False),
    Column("depth", Integer, nullable=False),
    Column("scope", Enum(RoleScope), nullable=False),
    Column("path", String, nullable=False),
    Column(
        "attributeTypeId",
        Integer,
        ForeignKey("AttributeTypes.id", ondelete="CASCADE"),
        nullable=True,
        key="attribute_type_id",
    ),
    Column(
        "entityTypeId",
        Integer,
        ForeignKey("EntityTypes.id", ondelete="CASCADE"),
        nullable=True,
        key="entity_type_id",
    ),
    Column("is_allow", Boolean, nullable=False),
    Index(
        "idx_ace_attribute_type_id",
        "attribute_type_id",
        postgresql_using="hash",
    ),
    Index("idx_ace_entity_type_id", "entity_type_id", postgresql_using="hash"),
    Index("idx_ace_role_id_id", "role_id", postgresql_using="hash"),
    Index("idx_ace_scope_hash", "scope", postgresql_using="hash"),
    Index("idx_ace_type_hash", "ace_type", postgresql_using="hash"),
)

ace_directory_memberships_table = Table(
    "AccessControlEntryDirectoryMemberships",
    metadata,
    Column(
        "access_control_entry_id",
        Integer,
        ForeignKey("AccessControlEntries.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "directory_id",
        Integer,
        ForeignKey("Directory.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

policies_table = Table(
    "Policies",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False, unique=True),
    Column("raw", JSON, nullable=False),
    Column("netmasks", ARRAY(CIDR), nullable=False, unique=True, index=True),
    Column("enabled", Boolean, server_default=true_, nullable=False),
    Column("priority", Integer, nullable=False),
    Column(
        "mfa_status",
        Enum(MFAFlags),
        server_default="DISABLED",
        nullable=False,
    ),
    Column("is_ldap", Boolean, server_default=true_, nullable=False),
    Column("is_http", Boolean, server_default=true_, nullable=False),
    Column("is_kerberos", Boolean, server_default=true_, nullable=False),
    Column(
        "bypass_no_connection",
        Boolean,
        server_default=false_,
        nullable=False,
    ),
    Column(
        "bypass_service_failure",
        Boolean,
        server_default=false_,
        nullable=False,
    ),
    Column("ldap_session_ttl", Integer, server_default="-1", nullable=False),
    Column(
        "http_session_ttl",
        Integer,
        server_default="28800",
        nullable=False,
    ),
    UniqueConstraint(
        "priority",
        name="priority_uc",
        deferrable=True,
        initially="DEFERRED",
    ),
)

audit_policies_table = Table(
    "AuditPolicies",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False, unique=True),
    Column("is_enabled", Boolean, server_default=false_, nullable=False),
    Column("severity", Enum(AuditSeverity), nullable=False),
)

audit_policy_triggers_table = Table(
    "AuditPolicyTriggers",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("is_ldap", Boolean, server_default=true_, nullable=False),
    Column("is_http", Boolean, server_default=true_, nullable=False),
    Column("operation_code", Integer, nullable=False),
    Column("object_class", String, nullable=False),
    Column("additional_info", JSON(none_as_null=True)),
    Column("is_operation_success", Boolean, nullable=False),
    Column(
        "audit_policy_id",
        Integer,
        ForeignKey("AuditPolicies.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    ),
    Index(
        "idx_trigger_search",
        "operation_code",
        "is_operation_success",
        "is_ldap",
        "is_http",
        postgresql_using="btree",
    ),
    Index(
        "idx_audit_policy_id_fk",
        "audit_policy_id",
        postgresql_using="hash",
    ),
)

audit_destinations_table = Table(
    "AuditDestinations",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False, unique=True),
    Column("service_type", Enum(AuditDestinationServiceType), nullable=False),
    Column("is_enabled", Boolean, server_default=true_, nullable=False),
    Column("host", String(255), nullable=False),
    Column("port", Integer, nullable=False),
    Column("protocol", Enum(AuditDestinationProtocolType), nullable=False),
)


mapper_registry.map_imperatively(
    CatalogueSetting,
    settings_table,
)

mapper_registry.map_imperatively(
    EntityType,
    entity_types_table,
    properties={
        "directories": relationship(
            Directory,
            back_populates="entity_type",
            lazy="raise",
            passive_deletes=True,
            cascade="all,delete-orphan",
            uselist=True,
            foreign_keys=directory_table.c.entity_type_id,
        ),
    },
)

mapper_registry.map_imperatively(
    PasswordPolicy,
    password_policies_table,
)

mapper_registry.map_imperatively(
    Directory,
    directory_table,
    properties={
        "parent": relationship(
            Directory,
            remote_side=[directory_table.c.id],
            backref="directories",
            cascade="all,delete",
            passive_deletes=True,
            lazy="raise",
            uselist=False,
            overlaps="directories",
        ),
        "entity_type": relationship(
            EntityType,
            back_populates="directories",
            lazy="raise",
            uselist=False,
        ),
        "attributes": relationship(
            Attribute,
            back_populates="directory",
            cascade="all, delete-orphan",
            passive_deletes=True,
            lazy="raise",
        ),
        "group": relationship(
            Group,
            uselist=False,
            back_populates="directory",
            lazy="raise",
            cascade="all",
            passive_deletes=True,
        ),
        "user": relationship(
            User,
            uselist=False,
            back_populates="directory",
            lazy="raise",
            cascade="all",
            passive_deletes=True,
        ),
        "groups": relationship(
            Group,
            secondary=directory_memberships_table,
            primaryjoin=directory_table.c.id
            == directory_memberships_table.c.directory_id,
            secondaryjoin=directory_memberships_table.c.group_id
            == groups_table.c.id,
            back_populates="members",
            cascade="all",
            passive_deletes=True,
            overlaps="group,directory",
            lazy="raise",
        ),
        "access_control_entries": relationship(
            "AccessControlEntry",
            secondary=ace_directory_memberships_table,
            primaryjoin=directory_table.c.id
            == ace_directory_memberships_table.c.directory_id,
            secondaryjoin=ace_directory_memberships_table.c.access_control_entry_id
            == access_control_entries_table.c.id,
            back_populates="directories",
            order_by=(
                desc(access_control_entries_table.c.depth),
                asc(access_control_entries_table.c.is_allow),
            ),
        ),
        "objectclass": synonym("object_class"),
        "objectguid": synonym("object_guid"),
        "objectsid": synonym("object_sid"),
        "whencreated": synonym("created_at"),
        "whenchanged": synonym("updated_at"),
    },
)

mapper_registry.map_imperatively(
    Attribute,
    attributes_table,
    properties={
        "directory": relationship(
            Directory,
            back_populates="attributes",
            lazy="raise",
        ),
        "directory_id": attributes_table.c.directory_id,
    },
)

mapper_registry.map_imperatively(
    User,
    users_table,
    properties={
        "directory": relationship(
            Directory,
            back_populates="user",
            lazy="joined",
        ),
        "groups": relationship(
            Group,
            secondary=directory_memberships_table,
            primaryjoin=users_table.c.directory_id
            == directory_memberships_table.c.directory_id,
            secondaryjoin=directory_memberships_table.c.group_id
            == groups_table.c.id,
            back_populates="users",
            passive_deletes=True,
            lazy="raise",
            overlaps="group,groups,directory",
        ),
        "samaccountname": synonym("sam_account_name"),
        "userprincipalname": synonym("user_principal_name"),
        "displayname": synonym("display_name"),
        "uid": synonym("sam_account_name"),
        "accountexpires": synonym("account_exp"),
    },
)

mapper_registry.map_imperatively(
    Group,
    groups_table,
    properties={
        "directory": relationship(Directory, back_populates="group"),
        "members": relationship(
            Directory,
            secondary=directory_memberships_table,
            back_populates="groups",
            passive_deletes=True,
            cascade="all",
            overlaps="group,groups,directory",
            lazy="raise",
        ),
        "parent_groups": relationship(
            Group,
            secondary=directory_memberships_table,
            primaryjoin=groups_table.c.directory_id
            == directory_memberships_table.c.directory_id,
            secondaryjoin=directory_memberships_table.c.group_id
            == groups_table.c.id,
            passive_deletes=True,
            cascade="all",
            lazy="raise",
            overlaps="group,groups,members,directory",
        ),
        "policies": relationship(
            NetworkPolicy,
            secondary=policy_memberships_table,
            primaryjoin=groups_table.c.id
            == policy_memberships_table.c.group_id,
            back_populates="groups",
            lazy="raise",
        ),
        "mfa_policies": relationship(
            NetworkPolicy,
            secondary=policy_mfa_memberships_table,
            primaryjoin=groups_table.c.id
            == policy_mfa_memberships_table.c.group_id,
            back_populates="mfa_groups",
            lazy="raise",
        ),
        "users": relationship(
            User,
            secondary=directory_memberships_table,
            primaryjoin=groups_table.c.id
            == directory_memberships_table.c.group_id,
            secondaryjoin=directory_memberships_table.c.directory_id
            == users_table.c.directory_id,
            back_populates="groups",
            passive_deletes=True,
            cascade="all",
            overlaps="directory,group,members,parent_groups,groups",
            lazy="raise",
        ),
        "roles": relationship(
            "Role",
            secondary=group_role_memberships_table,
            primaryjoin=groups_table.c.id
            == group_role_memberships_table.c.group_id,
            secondaryjoin=group_role_memberships_table.c.role_id
            == roles_table.c.id,
            back_populates="groups",
            lazy="raise",
        ),
    },
)

mapper_registry.map_imperatively(
    Role,
    roles_table,
    properties={
        "groups": relationship(
            Group,
            secondary=group_role_memberships_table,
            primaryjoin=group_role_memberships_table.c.role_id
            == roles_table.c.id,
            secondaryjoin=groups_table.c.id
            == group_role_memberships_table.c.group_id,
            back_populates="roles",
            passive_deletes=True,
            lazy="raise",
        ),
        "access_control_entries": relationship(
            "AccessControlEntry",
            back_populates="role",
            cascade="all, delete-orphan",
            passive_deletes=True,
            lazy="raise",
        ),
    },
)

mapper_registry.map_imperatively(
    AccessControlEntry,
    access_control_entries_table,
    properties={
        "role": relationship(
            Role,
            back_populates="access_control_entries",
            lazy="raise",
        ),
        "attribute_type": relationship(
            AttributeType,
            lazy="raise",
            uselist=False,
        ),
        "entity_type": relationship(EntityType, lazy="raise", uselist=False),
        "directories": relationship(
            Directory,
            secondary=ace_directory_memberships_table,
            back_populates="access_control_entries",
            lazy="raise",
        ),
    },
)

mapper_registry.map_imperatively(
    AttributeType,
    attribute_types_table,
)

mapper_registry.map_imperatively(
    ObjectClass,
    object_classes_table,
    properties={
        "superior": relationship(
            ObjectClass,
            remote_side=[object_classes_table.c.name],
            lazy="raise",
        ),
        "attribute_types_must": relationship(
            AttributeType,
            secondary=object_class_attr_must_table,
            lazy="raise",
        ),
        "attribute_types_may": relationship(
            AttributeType,
            secondary=object_class_attr_may_table,
            lazy="raise",
        ),
    },
)

mapper_registry.map_imperatively(
    NetworkPolicy,
    policies_table,
    properties={
        "groups": relationship(
            Group,
            secondary=policy_memberships_table,
            primaryjoin=policies_table.c.id
            == policy_memberships_table.c.policy_id,
            back_populates="policies",
            lazy="raise",
        ),
        "mfa_groups": relationship(
            Group,
            secondary=policy_mfa_memberships_table,
            primaryjoin=policies_table.c.id
            == policy_mfa_memberships_table.c.policy_id,
            back_populates="mfa_policies",
            lazy="raise",
        ),
    },
)

mapper_registry.map_imperatively(
    AuditPolicy,
    audit_policies_table,
    properties={
        "triggers": relationship(
            "AuditPolicyTrigger",
            back_populates="audit_policy",
            cascade="all, delete-orphan",
            passive_deletes=True,
            lazy="raise",
        ),
    },
)

mapper_registry.map_imperatively(
    AuditPolicyTrigger,
    audit_policy_triggers_table,
    properties={
        "audit_policy": relationship(
            AuditPolicy,
            back_populates="triggers",
            lazy="raise",
        ),
    },
)

mapper_registry.map_imperatively(
    AuditDestination,
    audit_destinations_table,
)
