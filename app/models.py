"""MultiDirectory LDAP models.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, ClassVar, Literal

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
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

DistinguishedNamePrefix = Literal["cn", "ou", "dc"]


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
        ForeignKey("Groups.id", ondelete="CASCADE"), primary_key=True
    )

    directory_id: Mapped[int] = mapped_column(
        ForeignKey("Directory.id", ondelete="CASCADE"), primary_key=True
    )


class PolicyMembership(Base):
    """Policy membership - path m2m relationship."""

    __tablename__ = "PolicyMemberships"
    group_id: Mapped[int] = mapped_column(
        ForeignKey("Groups.id", ondelete="CASCADE"), primary_key=True
    )
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("Policies.id", ondelete="CASCADE"), primary_key=True
    )


class PolicyMFAMembership(Base):
    """Policy membership - path m2m relationship."""

    __tablename__ = "PolicyMFAMemberships"
    group_id: Mapped[int] = mapped_column(
        ForeignKey("Groups.id", ondelete="CASCADE"), primary_key=True
    )
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("Policies.id", ondelete="CASCADE"), primary_key=True
    )


class AccessPolicyMembership(Base):
    """Directory - policy m2m relationship."""

    __tablename__ = "AccessPolicyMemberships"
    dir_id: Mapped[int] = mapped_column(
        ForeignKey("Directory.id", ondelete="CASCADE"), primary_key=True
    )
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("AccessPolicies.id", ondelete="CASCADE"), primary_key=True
    )


class GroupAccessPolicyMembership(Base):
    """Directory - policy m2m relationship."""

    __tablename__ = "GroupAccessPolicyMemberships"
    group_id: Mapped[int] = mapped_column(
        ForeignKey("Groups.id", ondelete="CASCADE"), primary_key=True
    )
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("AccessPolicies.id", ondelete="CASCADE"), primary_key=True
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
    depth: Mapped[int]

    object_sid: Mapped[str] = mapped_column("objectSid")
    objectsid: Mapped[str] = synonym("object_sid")

    password_policy_id: Mapped[int] = mapped_column(
        ForeignKey("PasswordPolicies.id"), nullable=True
    )

    object_guid: Mapped[uuid.UUID] = mapped_column(
        "objectGUID",
        postgresql.UUID(as_uuid=True),
        default=uuid.uuid4,
        nullable=False,
    )
    objectguid: Mapped[str] = synonym("object_guid")

    path: Mapped[list[str]] = mapped_column(
        postgresql.ARRAY(String), nullable=False, index=True
    )

    attributes: Mapped[list[Attribute]] = relationship(
        "Attribute",
        cascade="all",
        passive_deletes=True,
    )
    group: Mapped[Group] = relationship(
        "Group",
        uselist=False,
        cascade="all",
        passive_deletes=True,
        lazy="selectin",
    )
    user: Mapped[User] = relationship(
        "User",
        uselist=False,
        lazy="selectin",
        cascade="all",
        passive_deletes=True,
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
        lazy="selectin",
    )
    access_policies: Mapped[list[AccessPolicy]] = relationship(
        "AccessPolicy",
        secondary=AccessPolicyMembership.__table__,
        primaryjoin="Directory.id == AccessPolicyMembership.dir_id",
        secondaryjoin="AccessPolicyMembership.policy_id == AccessPolicy.id",
        back_populates="directories",
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
        "displayName", nullable=True
    )
    password: Mapped[str] = mapped_column(nullable=True)

    samaccountname: Mapped[str] = synonym("sam_accout_name")
    userprincipalname: Mapped[str] = synonym("user_principal_name")
    displayname: Mapped[str] = synonym("display_name")
    uid: Mapped[str] = synonym("sam_accout_name")
    accountexpires: Mapped[str] = synonym("account_exp")

    last_logon: Mapped[datetime | None] = mapped_column(
        "lastLogon", DateTime(timezone=True)
    )
    account_exp: Mapped[datetime | None] = mapped_column(
        "accountExpires", DateTime(timezone=True)
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
        lazy="selectin",
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
        lazy="joined",
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

    access_policies: Mapped[list[AccessPolicy]] = relationship(
        "AccessPolicy",
        secondary=GroupAccessPolicyMembership.__table__,
        primaryjoin="Group.id == GroupAccessPolicyMembership.group_id",
        secondaryjoin=(
            "GroupAccessPolicyMembership.policy_id == AccessPolicy.id"
        ),
        back_populates="groups",
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

    directory_id: Mapped[int] = mapped_column(
        "directoryId",
        ForeignKey("Directory.id", ondelete="CASCADE"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(nullable=False, index=True)
    value: Mapped[str | None] = mapped_column(nullable=True)
    bvalue: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    directory: Mapped[Directory] = relationship(
        "Directory",
        back_populates="attributes",
        uselist=False,
    )


class MFAFlags(int, enum.Enum):
    """Two-Factor auth action."""

    DISABLED = 0
    ENABLED = 1
    WHITELIST = 2


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
        nullable=False, server_default="-1")

    http_session_ttl: Mapped[int] = mapped_column(
        nullable=False, server_default="28800")

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
        nullable=False, server_default="4"
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


class AccessPolicy(Base):
    """Access policy."""

    __tablename__ = "AccessPolicies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    can_read: Mapped[nbool]
    can_add: Mapped[nbool]
    can_modify: Mapped[nbool]
    can_delete: Mapped[nbool]

    directories: Mapped[list[Directory]] = relationship(
        "Directory",
        secondary=AccessPolicyMembership.__table__,
        order_by="Directory.depth",
        back_populates="access_policies",
    )

    groups: Mapped[list[Group]] = relationship(
        "Group",
        secondary=GroupAccessPolicyMembership.__table__,
        back_populates="access_policies",
    )
