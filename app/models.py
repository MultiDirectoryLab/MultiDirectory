"""MultiDirectory LDAP models.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, ClassVar, Literal

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    asc,
    desc,
    func,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    backref,
    mapped_column,
    relationship,
    synonym,
)
from sqlalchemy.schema import DDLElement
from sqlalchemy.sql import expression
from sqlalchemy.sql.compiler import DDLCompiler

from enums import (
    AceType,
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
    AuditSeverity,
    MFAFlags,
    RoleScope,
)

type DistinguishedNamePrefix = Literal["cn", "ou", "dc"]
type KindType = Literal["STRUCTURAL", "ABSTRACT", "AUXILIARY"]


class Base(DeclarativeBase, AsyncAttrs):
    """Declarative base model."""


nbool = Annotated[bool, mapped_column(nullable=False)]
tbool = Annotated[
    bool,
    mapped_column(server_default=expression.true(), nullable=False),
]
fbool = Annotated[
    bool,
    mapped_column(server_default=expression.false(), nullable=False),
]

UniqueConstraint.argument_for("postgresql", "nulls_not_distinct", None)


@compiles(UniqueConstraint, "postgresql")
def compile_create_uc(
    create: DDLElement,
    compiler: DDLCompiler,
    **kw: dict,
) -> str:
    """Add NULLS NOT DISTINCT if its in args."""
    stmt = compiler.visit_unique_constraint(create, **kw)
    postgresql_opts = create.dialect_options["postgresql"]  # type: ignore

    if postgresql_opts.get("nulls_not_distinct"):
        return stmt.rstrip().replace("UNIQUE (", "UNIQUE NULLS NOT DISTINCT (")
    return stmt


class CatalogueSetting(Base):
    """Catalogue params unit."""

    __tablename__ = "Settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(nullable=False, index=True)
    value: Mapped[str] = mapped_column(nullable=False)


class DirectoryMembership(Base):
    """Directory membership - path m2m relationship."""

    __tablename__ = "DirectoryMemberships"
    group_id: Mapped[int] = mapped_column(
        ForeignKey("Groups.id", ondelete="CASCADE"),
        primary_key=True,
    )

    directory_id: Mapped[int] = mapped_column(
        ForeignKey("Directory.id", ondelete="CASCADE"),
        primary_key=True,
    )


class PolicyMembership(Base):
    """Policy membership - path m2m relationship."""

    __tablename__ = "PolicyMemberships"
    group_id: Mapped[int] = mapped_column(
        ForeignKey("Groups.id", ondelete="CASCADE"),
        primary_key=True,
    )
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("Policies.id", ondelete="CASCADE"),
        primary_key=True,
    )


class PolicyMFAMembership(Base):
    """Policy membership - path m2m relationship."""

    __tablename__ = "PolicyMFAMemberships"
    group_id: Mapped[int] = mapped_column(
        ForeignKey("Groups.id", ondelete="CASCADE"),
        primary_key=True,
    )
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("Policies.id", ondelete="CASCADE"),
        primary_key=True,
    )


class AccessControlEntryDirectoryMembership(Base):
    """Access Control Entry - Directory m2m relationship."""

    __tablename__ = "AccessControlEntryDirectoryMemberships"

    access_control_entry_id: Mapped[int] = mapped_column(
        ForeignKey("AccessControlEntries.id", ondelete="CASCADE"),
        primary_key=True,
    )
    directory_id: Mapped[int] = mapped_column(
        ForeignKey("Directory.id", ondelete="CASCADE"),
        primary_key=True,
    )


class GroupRoleMembership(Base):
    """Group - role m2m relationship."""

    __tablename__ = "GroupRoleMemberships"

    group_id: Mapped[int] = mapped_column(
        ForeignKey("Groups.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_id: Mapped[int] = mapped_column(
        ForeignKey("Roles.id", ondelete="CASCADE"),
        primary_key=True,
    )


class EntityType(Base):
    """Entity Type."""

    __tablename__ = "EntityTypes"
    __table_args__ = (
        Index(
            "idx_entity_types_name_gin_trgm",
            text("name gin_trgm_ops"),
            postgresql_using="gin",
            postgresql_ops={"name": "gin_trgm_ops"},
        ),
    )
    id: Mapped[int] = mapped_column(
        Integer(),
        Identity(start=1, always=True),
        ForeignKey("Directory.entity_type_id", ondelete="SET NULL"),
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )
    object_class_names: Mapped[list[str]] = mapped_column(
        postgresql.ARRAY(String),
        index=True,
    )
    is_system: Mapped[bool] = mapped_column(nullable=False)
    directories: Mapped[list[Directory]] = relationship(
        "Directory",
        passive_deletes=True,
        lazy="raise",
        uselist=True,
        foreign_keys="Directory.entity_type_id",
    )

    @property
    def object_class_names_set(self) -> set[str]:
        """Get object class names."""
        return set(self.object_class_names)

    @classmethod
    def generate_entity_type_name(cls, directory: Directory) -> str:
        """Generate entity type name based on Directory."""
        return f"{directory.name}_entity_type_{directory.id}"


class AccessControlEntry(Base):
    """Access Control Entry (ACE) model."""

    __tablename__ = "AccessControlEntries"

    id: Mapped[int] = mapped_column(primary_key=True)
    role_id: Mapped[int] = mapped_column(
        "roleId",
        ForeignKey("Roles.id", ondelete="CASCADE"),
        nullable=False,
    )

    ace_type: Mapped[AceType] = mapped_column(
        Enum(AceType),
        nullable=False,
        index=True,
    )

    depth: Mapped[int]

    scope: Mapped[RoleScope] = mapped_column(
        Enum(RoleScope),
        nullable=False,
        index=True,
    )

    path: Mapped[str] = mapped_column(
        nullable=False,
        unique=False,
    )

    attribute_type_id: Mapped[int | None] = mapped_column(
        "attributeTypeId",
        ForeignKey("AttributeTypes.id", ondelete="CASCADE"),
        nullable=True,
    )

    entity_type_id: Mapped[int | None] = mapped_column(
        "entityTypeId",
        ForeignKey("EntityTypes.id", ondelete="CASCADE"),
        nullable=True,
    )

    is_allow: Mapped[nbool]

    role: Mapped[Role] = relationship(
        "Role",
        back_populates="access_control_entries",
        uselist=False,
        lazy="raise",
    )

    attribute_type: Mapped[AttributeType] = relationship(
        "AttributeType",
        uselist=False,
        lazy="raise",
    )

    entity_type: Mapped[EntityType] = relationship(
        "EntityType",
        uselist=False,
        lazy="raise",
    )

    directories: Mapped[list[Directory]] = relationship(
        "Directory",
        secondary=AccessControlEntryDirectoryMembership.__table__,
        order_by="Directory.depth",
        back_populates="access_control_entries",
        lazy="raise",
    )

    @property
    def attribute_type_name(self) -> str | None:
        """Get attribute type name."""
        return (
            self.attribute_type.name.lower() if self.attribute_type else None
        )

    @property
    def entity_type_name(self) -> str | None:
        """Get entity type name."""
        return self.entity_type.name if self.entity_type else None

    def __repr__(self) -> str:
        """Representation of AccessControlEntry."""
        return (
            f"<AccessControlEntry id={self.id} "
            f"role_id={self.role_id} "
            f"attribute_type_id={self.attribute_type_id} "
            f"entity_type_id={self.entity_type_id} "
            f"is_allow={self.is_allow}>"
            f" (type={self.ace_type}, "
            f"depth={self.depth})"
        )


class Directory(Base):
    """Chierarcy of catalogue unit."""

    __tablename__ = "Directory"

    id: Mapped[int] = mapped_column(primary_key=True)

    parent_id: Mapped[int] = mapped_column(
        "parentId",
        ForeignKey("Directory.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )

    parent: Mapped[Directory | None] = relationship(
        lambda: Directory,
        remote_side="Directory.id",
        backref=backref("directories", cascade="all,delete", viewonly=True),
        uselist=False,
    )
    entity_type_id: Mapped[int | None] = mapped_column(
        "entity_type_id",
        ForeignKey("EntityTypes.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )

    entity_type: Mapped[EntityType | None] = relationship(
        EntityType,
        uselist=False,
        foreign_keys=[entity_type_id],
        lazy="raise",
        overlaps="directories",
    )

    @property
    def entity_type_object_class_names_set(self) -> set[str]:
        """Get object class names of entity type."""
        return (
            self.entity_type.object_class_names_set
            if self.entity_type
            else set()
        )

    @property
    def object_class_names_set(self) -> set[str]:
        return set(
            self.attributes_dict.get("objectClass", [])
            + self.attributes_dict.get("objectclass", []),
        )

    object_class: Mapped[str] = mapped_column("objectClass", nullable=False)
    objectclass: Mapped[str] = synonym("object_class")

    name: Mapped[str] = mapped_column(nullable=False)
    rdname: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        "whenCreated",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        "whenChanged",
        DateTime(timezone=True),
        onupdate=func.now(),
        nullable=True,
    )
    depth: Mapped[int] = mapped_column(index=True)

    object_sid: Mapped[str] = mapped_column("objectSid")
    objectsid: Mapped[str] = synonym("object_sid")

    password_policy_id: Mapped[int] = mapped_column(
        ForeignKey("PasswordPolicies.id"),
        nullable=True,
    )

    object_guid: Mapped[uuid.UUID] = mapped_column(
        "objectGUID",
        postgresql.UUID(as_uuid=True),
        default=uuid.uuid4,
        nullable=False,
    )
    objectguid: Mapped[str] = synonym("object_guid")

    path: Mapped[list[str]] = mapped_column(
        postgresql.ARRAY(String),
        nullable=False,
        index=True,
    )

    attributes: Mapped[list[Attribute]] = relationship(
        "Attribute",
        cascade="all",
        passive_deletes=True,
        lazy="raise",
    )

    @property
    def attributes_dict(self) -> defaultdict[str, list[str]]:
        attributes = defaultdict(list)
        for attribute in self.attributes:
            attributes[attribute.name].extend(attribute.values)
        return attributes

    group: Mapped[Group] = relationship(
        "Group",
        uselist=False,
        cascade="all",
        passive_deletes=True,
        lazy="joined",
    )
    user: Mapped[User] = relationship(
        "User",
        uselist=False,
        cascade="all",
        passive_deletes=True,
        lazy="joined",
    )
    groups: Mapped[list[Group]] = relationship(
        "Group",
        secondary=DirectoryMembership.__table__,
        primaryjoin="Directory.id == DirectoryMembership.directory_id",
        secondaryjoin="DirectoryMembership.group_id == Group.id",
        back_populates="members",
        cascade="all",
        passive_deletes=True,
        overlaps="group,directory",
        lazy="raise",
    )
    access_control_entries: Mapped[list[AccessControlEntry]] = relationship(
        "AccessControlEntry",
        secondary=AccessControlEntryDirectoryMembership.__table__,
        primaryjoin="Directory.id == AccessControlEntryDirectoryMembership.directory_id",  # noqa: E501
        secondaryjoin="AccessControlEntryDirectoryMembership.access_control_entry_id == AccessControlEntry.id",  # noqa: E501
        back_populates="directories",
        order_by=(
            desc(AccessControlEntry.depth),
            asc(AccessControlEntry.is_allow),
        ),
    )

    __table_args__ = (
        UniqueConstraint(
            "parentId",
            "name",
            postgresql_nulls_not_distinct=True,
            name="name_parent_uc",
        ),
    )

    search_fields = {
        "name": "name",
        "objectguid": "objectGUID",
        "objectsid": "objectSid",
    }

    ro_fields = {
        "uid",
        "whenCreated",
        "lastLogon",
        "authTimestamp",
        "objectGUID",
        "objectSid",
        "entityTypeName",
    }

    def get_dn_prefix(self) -> DistinguishedNamePrefix:
        """Get distinguished name prefix."""
        return {
            "organizationalUnit": "ou",
            "domain": "dc",
        }.get(self.object_class, "cn")  # type: ignore

    def get_dn(self, dn: str = "cn") -> str:
        """Get distinguished name."""
        return f"{dn}={self.name}"

    @property
    def is_domain(self) -> bool:
        """Is directory domain."""
        return not self.parent_id and self.object_class == "domain"

    @property
    def host_principal(self) -> str:
        """Principal computer name."""
        return f"host/{self.name}"

    @property
    def path_dn(self) -> str:
        """Get DN from path."""
        return ",".join(reversed(self.path))

    def create_path(
        self,
        parent: Directory | None = None,
        dn: str = "cn",
    ) -> None:
        """Create path from a new directory."""
        pre_path: list[str] = parent.path if parent else []
        self.path = pre_path + [self.get_dn(dn)]
        self.depth = len(self.path)
        self.rdname = dn

    def __str__(self) -> str:
        """Dir name."""
        return f"Directory({self.name})"

    def __repr__(self) -> str:
        """Dir id and name."""
        return f"Directory({self.id}:{self.name})"


class User(Base):
    """Users data from db."""

    __tablename__ = "Users"

    id: Mapped[int] = mapped_column(primary_key=True)

    directory_id: Mapped[int] = mapped_column(
        "directoryId",
        ForeignKey("Directory.id", ondelete="CASCADE"),
        nullable=False,
    )

    directory: Mapped[Directory] = relationship(
        "Directory",
        back_populates="user",
        uselist=False,
        lazy="joined",
    )

    sam_accout_name: Mapped[str] = mapped_column(
        "sAMAccountName",
        nullable=False,
        unique=True,
    )
    user_principal_name: Mapped[str] = mapped_column(
        "userPrincipalName",
        nullable=False,
        unique=True,
    )

    mail: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(
        "displayName",
        nullable=True,
    )
    password: Mapped[str] = mapped_column(nullable=True)

    samaccountname: Mapped[str] = synonym("sam_accout_name")
    userprincipalname: Mapped[str] = synonym("user_principal_name")
    displayname: Mapped[str] = synonym("display_name")
    uid: Mapped[str] = synonym("sam_accout_name")
    accountexpires: Mapped[str] = synonym("account_exp")

    last_logon: Mapped[datetime | None] = mapped_column(
        "lastLogon",
        DateTime(timezone=True),
    )
    account_exp: Mapped[datetime | None] = mapped_column(
        "accountExpires",
        DateTime(timezone=True),
    )

    search_fields = {
        "mail": "mail",
        "samaccountname": "sAMAccountName",
        "userprincipalname": "userPrincipalName",
        "displayname": "displayName",
        "uid": "uid",
        "accountexpires": "accountExpires",
    }

    fields = {
        "loginshell": "loginShell",
        "uidnumber": "uidNumber",
        "homedirectory": "homeDirectory",
    }

    password_history: Mapped[list[str]] = mapped_column(
        MutableList.as_mutable(postgresql.ARRAY(String)),
        server_default="{}",
        nullable=False,
    )

    groups: Mapped[list[Group]] = relationship(
        "Group",
        secondary=DirectoryMembership.__table__,
        primaryjoin="User.directory_id == DirectoryMembership.directory_id",
        secondaryjoin="DirectoryMembership.group_id == Group.id",
        back_populates="users",
        cascade="all",
        passive_deletes=True,
        overlaps="group,groups,directory",
    )

    def get_upn_prefix(self) -> str:
        """Get userPrincipalName prefix."""
        return self.user_principal_name.split("@")[0]

    def __str__(self) -> str:
        """User show."""
        return f"User({self.sam_accout_name})"

    def __repr__(self) -> str:
        """User map with dir id."""
        return f"User({self.directory_id}:{self.sam_accout_name})"

    def is_expired(self) -> bool:
        """Check AccountExpires."""
        if self.account_exp is None:
            return False

        now = datetime.now(tz=timezone.utc)
        user_account_exp = self.account_exp.astimezone(timezone.utc)

        return now > user_account_exp


class Group(Base):
    """Group params."""

    __tablename__ = "Groups"

    id: Mapped[int] = mapped_column(primary_key=True)

    directory_id: Mapped[int] = mapped_column(
        "directoryId",
        ForeignKey("Directory.id", ondelete="CASCADE"),
        nullable=False,
    )

    directory: Mapped[Directory] = relationship(
        "Directory",
        back_populates="group",
        uselist=False,
    )

    search_fields: ClassVar[dict[str, str]] = {}

    members: Mapped[list[Directory]] = relationship(
        "Directory",
        secondary=DirectoryMembership.__table__,
        back_populates="groups",
        cascade="all",
        passive_deletes=True,
        overlaps="group,groups,directory",
    )

    parent_groups: Mapped[list[Group]] = relationship(
        "Group",
        secondary=DirectoryMembership.__table__,
        primaryjoin="Group.directory_id == DirectoryMembership.directory_id",
        secondaryjoin="DirectoryMembership.group_id == Group.id",
        cascade="all",
        passive_deletes=True,
        overlaps="group,groups,members,directory",
    )

    policies: Mapped[list[NetworkPolicy]] = relationship(
        "NetworkPolicy",
        secondary=PolicyMembership.__table__,
        primaryjoin="Group.id == PolicyMembership.group_id",
        back_populates="groups",
    )

    mfa_policies: Mapped[list[NetworkPolicy]] = relationship(
        "NetworkPolicy",
        secondary=PolicyMFAMembership.__table__,
        primaryjoin="Group.id == PolicyMFAMembership.group_id",
        back_populates="mfa_groups",
    )

    users: Mapped[list[User]] = relationship(
        "User",
        secondary=DirectoryMembership.__table__,
        primaryjoin="Group.id == DirectoryMembership.group_id",
        secondaryjoin="DirectoryMembership.directory_id == User.directory_id",
        back_populates="groups",
        cascade="all",
        passive_deletes=True,
        overlaps="directory,group,members,parent_groups,groups",
    )

    roles: Mapped[list[Role]] = relationship(
        "Role",
        secondary=GroupRoleMembership.__table__,
        primaryjoin="Group.id == GroupRoleMembership.group_id",
        secondaryjoin="GroupRoleMembership.role_id == Role.id",
        back_populates="groups",
        lazy="raise",
    )

    def __str__(self) -> str:
        """Group id."""
        return f"Group({self.id})"

    def __repr__(self) -> str:
        """Group id and dir id."""
        return f"Group({self.id}:{self.directory_id})"


class Attribute(Base):
    """Attributes data."""

    __tablename__ = "Attributes"
    __table_args__ = (
        CheckConstraint(
            "(value IS NULL) <> (bvalue IS NULL)",
            name="constraint_value_xor_bvalue",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    directory: Mapped[Directory] = relationship(
        "Directory",
        back_populates="attributes",
        uselist=False,
    )
    directory_id: Mapped[int] = mapped_column(
        "directoryId",
        ForeignKey("Directory.id", ondelete="CASCADE"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(nullable=False, index=True)
    value: Mapped[str | None] = mapped_column(nullable=True)
    bvalue: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    @property
    def _decoded_value(self) -> str | None:
        """Get attribute value."""
        if self.value:
            return self.value
        if self.bvalue:
            return self.bvalue.decode("latin-1")
        return None

    @property
    def values(self) -> list[str]:
        """Get attribute value by list."""
        return [self._decoded_value] if self._decoded_value else []

    def __str__(self) -> str:
        """Attribute name and value."""
        return f"Attribute({self.name}:{self._decoded_value})"

    def __repr__(self) -> str:
        """Attribute name and value."""
        return f"Attribute({self.name}:{self._decoded_value})"


class AttributeType(Base):
    """Attribute Type."""

    __tablename__ = "AttributeTypes"
    __table_args__ = (
        Index(
            "idx_attribute_types_name_gin_trgm",
            text("name gin_trgm_ops"),
            postgresql_using="gin",
            postgresql_ops={"name": "gin_trgm_ops"},
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    oid: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )
    syntax: Mapped[str] = mapped_column(String(255), nullable=False)
    single_value: Mapped[bool]
    no_user_modification: Mapped[bool]
    is_system: Mapped[bool]  # NOTE: it's not equal `NO-USER-MODIFICATION`

    def get_raw_definition(self) -> str:
        """Format SQLAlchemy Attribute Type object to LDAP definition."""
        if not self.oid or not self.name or not self.syntax:
            err_msg = f"{self}: Fields 'oid', 'name', and 'syntax' are required for LDAP definition."  # noqa: E501
            raise ValueError(err_msg)

        chunks = [
            "(",
            f"{self.oid}",
            f"NAME '{self.name}'",
            f"SYNTAX '{self.syntax}'",
        ]

        if self.single_value:
            chunks.append("SINGLE-VALUE")
        if self.no_user_modification:
            chunks.append("NO-USER-MODIFICATION")
        chunks.append(")")
        return " ".join(chunks)

    def __str__(self) -> str:
        """AttributeType name."""
        return f"AttributeType({self.name})"

    def __repr__(self) -> str:
        """AttributeType oid and name."""
        return f"AttributeType({self.oid}:{self.name})"


class ObjectClassAttributeTypeMustMembership(Base):
    """ObjectClass - MustAttributeType m2m relationship."""

    __tablename__ = "ObjectClassAttributeTypeMustMemberships"

    __table_args__ = (
        UniqueConstraint(
            "attribute_type_name",
            "object_class_name",
            name="object_class_must_attribute_type_uc",
        ),
    )

    attribute_type_name: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("AttributeTypes.name", ondelete="CASCADE"),
        primary_key=True,
    )
    object_class_name: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("ObjectClasses.name", ondelete="CASCADE"),
        primary_key=True,
    )


class ObjectClassAttributeTypeMayMembership(Base):
    """ObjectClass - MayAttributeType m2m relationship."""

    __tablename__ = "ObjectClassAttributeTypeMayMemberships"

    __table_args__ = (
        UniqueConstraint(
            "attribute_type_name",
            "object_class_name",
            name="object_class_may_attribute_type_uc",
        ),
    )

    attribute_type_name: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("AttributeTypes.name", ondelete="CASCADE"),
        primary_key=True,
    )
    object_class_name: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("ObjectClasses.name", ondelete="CASCADE"),
        primary_key=True,
    )


class ObjectClass(Base):
    """Object Class."""

    __tablename__ = "ObjectClasses"
    __table_args__ = (
        Index(
            "idx_object_classes_name_gin_trgm",
            text("name gin_trgm_ops"),
            postgresql_using="gin",
            postgresql_ops={"name": "gin_trgm_ops"},
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    oid: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )
    superior_name: Mapped[str | None] = mapped_column(
        String(255),
        ForeignKey("ObjectClasses.name", ondelete="SET NULL"),
        nullable=True,
    )
    superior: Mapped[ObjectClass | None] = relationship(
        "ObjectClass",
        remote_side="ObjectClass.name",
        uselist=False,
    )
    kind: Mapped[KindType] = mapped_column(nullable=False)
    is_system: Mapped[bool]

    attribute_types_must: Mapped[list[AttributeType]] = relationship(
        "AttributeType",
        secondary=ObjectClassAttributeTypeMustMembership.__table__,
        primaryjoin="ObjectClass.name == ObjectClassAttributeTypeMustMembership.object_class_name",  # noqa: E501
        secondaryjoin="ObjectClassAttributeTypeMustMembership.attribute_type_name == AttributeType.name",  # noqa: E501
        lazy="selectin",
    )

    attribute_types_may: Mapped[list[AttributeType]] = relationship(
        "AttributeType",
        secondary=ObjectClassAttributeTypeMayMembership.__table__,
        primaryjoin="ObjectClass.name == ObjectClassAttributeTypeMayMembership.object_class_name",  # noqa: E501
        secondaryjoin="ObjectClassAttributeTypeMayMembership.attribute_type_name == AttributeType.name",  # noqa: E501
        lazy="selectin",
    )

    def get_raw_definition(self) -> str:
        """Format SQLAlchemy Object Class object to LDAP definition."""
        if not self.oid or not self.name or not self.kind:
            err_msg = f"{self}: Fields 'oid', 'name', and 'kind' are required for LDAP definition."  # noqa: E501
            raise ValueError(err_msg)

        chunks = ["(", f"{self.oid}", f"NAME '{self.name}'"]

        if self.superior_name:
            chunks.append(f"SUP {self.superior_name}")

        chunks.append(self.kind)

        if self.attribute_type_names_must:
            chunks.append(
                f"MUST ({' $ '.join(self.attribute_type_names_must)} )",
            )
        if self.attribute_type_names_may:
            chunks.append(
                f"MAY ({' $ '.join(self.attribute_type_names_may)} )",
            )
        chunks.append(")")
        return " ".join(chunks)

    @property
    def attribute_type_names_must(self) -> list[str]:
        """Display attribute types must."""
        return [attr.name for attr in self.attribute_types_must]

    @property
    def attribute_type_names_may(self) -> list[str]:
        """Display attribute types may."""
        return [attr.name for attr in self.attribute_types_may]

    def __str__(self) -> str:
        """ObjectClass name."""
        return f"ObjectClass({self.name})"

    def __repr__(self) -> str:
        """ObjectClass oid and name."""
        return f"ObjectClass({self.oid}:{self.name})"


class NetworkPolicy(Base):
    """Network policy data."""

    __tablename__ = "Policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(nullable=False, unique=True)

    raw: Mapped[dict | list] = mapped_column(postgresql.JSON, nullable=False)
    netmasks: Mapped[list[IPv4Network | IPv4Address]] = mapped_column(
        postgresql.ARRAY(postgresql.CIDR),
        nullable=False,
        unique=True,
        index=True,
    )

    enabled: Mapped[tbool]
    priority: Mapped[int] = mapped_column(nullable=False)

    priority_uc = UniqueConstraint(
        "priority",
        name="priority_uc",
        deferrable=True,
        initially="DEFERRED",
    )

    groups: Mapped[list[Group]] = relationship(
        "Group",
        secondary=PolicyMembership.__table__,
        back_populates="policies",
    )
    mfa_status: Mapped[MFAFlags] = mapped_column(
        Enum(MFAFlags),
        server_default="DISABLED",
        nullable=False,
    )

    is_ldap: Mapped[tbool]
    is_http: Mapped[tbool]
    is_kerberos: Mapped[tbool]

    mfa_groups: Mapped[list[Group]] = relationship(
        "Group",
        secondary=PolicyMFAMembership.__table__,
        back_populates="mfa_policies",
    )

    bypass_no_connection: Mapped[fbool]
    bypass_service_failure: Mapped[fbool]

    ldap_session_ttl: Mapped[int] = mapped_column(
        nullable=False,
        server_default="-1",
    )

    http_session_ttl: Mapped[int] = mapped_column(
        nullable=False,
        server_default="28800",
    )


class PasswordPolicy(Base):
    """Password policy."""

    __tablename__ = "PasswordPolicies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        server_default="Default Policy",
    )

    password_history_length: Mapped[int] = mapped_column(
        nullable=False,
        server_default="4",
    )
    maximum_password_age_days: Mapped[int] = mapped_column(
        nullable=False,
        server_default="0",
    )
    minimum_password_age_days: Mapped[int] = mapped_column(
        nullable=False,
        server_default="0",
    )
    minimum_password_length: Mapped[int] = mapped_column(
        nullable=False,
        server_default="7",
    )
    password_must_meet_complexity_requirements: Mapped[tbool]


class Role(Base):
    """Role."""

    __tablename__ = "Roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    creator_upn: Mapped[str | None] = mapped_column(
        nullable=True,
        unique=False,
    )

    is_system: Mapped[nbool]

    created_at: Mapped[datetime] = mapped_column(
        "whenCreated",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    groups: Mapped[list[Group]] = relationship(
        "Group",
        secondary=GroupRoleMembership.__table__,
        primaryjoin="GroupRoleMembership.role_id == Role.id",
        secondaryjoin="Group.id == GroupRoleMembership.group_id",
        back_populates="roles",
        lazy="raise",
        passive_deletes=True,
    )

    access_control_entries: Mapped[list[AccessControlEntry]] = relationship(
        "AccessControlEntry",
        cascade="all",
        lazy="raise",
        back_populates="role",
        passive_deletes=True,
    )


class AuditPolicy(Base):
    """Audit policy."""

    __tablename__ = "AuditPolicies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    is_enabled: Mapped[bool] = mapped_column(
        nullable=False, server_default=expression.false()
    )
    severity: Mapped[AuditSeverity] = mapped_column(
        Enum(AuditSeverity),
        nullable=False,
    )

    triggers: Mapped[list[AuditPolicyTrigger]] = relationship(
        "AuditPolicyTrigger",
        back_populates="audit_policy",
        cascade="all",
        passive_deletes=True,
        lazy="raise",
    )


class AuditPolicyTrigger(Base):
    """Audit policy triggers."""

    __tablename__ = "AuditPolicyTriggers"

    id: Mapped[int] = mapped_column(primary_key=True)
    is_ldap: Mapped[tbool]
    is_http: Mapped[tbool]
    operation_code: Mapped[int]
    object_class: Mapped[str]
    additional_info: Mapped[dict] = mapped_column(
        postgresql.JSON, nullable=True
    )
    operation_success: Mapped[nbool]

    audit_policy_id: Mapped[int] = mapped_column(
        "audit_policy_id",
        ForeignKey("AuditPolicies.id", ondelete="CASCADE"),
        nullable=False,
    )

    audit_policy: Mapped[AuditPolicy] = relationship(
        "AuditPolicy",
        uselist=False,
        back_populates="triggers",
        lazy="raise",
    )


class AuditDestination(Base):
    """Audit destinations."""

    __tablename__ = "AuditDestinations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    service_type: Mapped[AuditDestinationServiceType] = mapped_column(
        Enum(AuditDestinationServiceType), nullable=False
    )
    is_enabled: Mapped[tbool]
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(nullable=False)
    protocol: Mapped[AuditDestinationProtocolType] = mapped_column(
        Enum(AuditDestinationProtocolType),
        nullable=False,
    )
