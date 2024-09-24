"""MultiDirectory LDAP models.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import (
    Mapped,
    backref,
    declarative_mixin,
    declared_attr,
    relationship,
    synonym,
)
from sqlalchemy.schema import DDLElement
from sqlalchemy.sql import expression
from sqlalchemy.sql.compiler import DDLCompiler

from .database import Base

DistinguishedNamePrefix = Literal['cn', 'ou', 'dc']

UniqueConstraint.argument_for("postgresql", 'nulls_not_distinct', None)


@compiles(UniqueConstraint, "postgresql")
def compile_create_uc(
        create: DDLElement, compiler: DDLCompiler, **kw: Any) -> str:
    """Add NULLS NOT DISTINCT if its in args."""
    stmt = compiler.visit_unique_constraint(create, **kw)
    postgresql_opts = create.dialect_options["postgresql"]  # type: ignore

    if postgresql_opts.get("nulls_not_distinct"):
        return stmt.rstrip().replace("UNIQUE (", "UNIQUE NULLS NOT DISTINCT (")
    return stmt


class CatalogueSetting(Base):
    """Catalogue params unit."""

    __tablename__ = "Settings"

    id = Column(Integer, primary_key=True)  # noqa: A003
    name = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False)


class DirectoryMembership(Base):
    """Directory membership - path m2m relationship."""

    __tablename__ = "DirectoryMemberships"
    group_id = Column(Integer, ForeignKey("Groups.id"), primary_key=True)
    directory_id = Column(
        Integer, ForeignKey("Directory.id"), primary_key=True)

    group: 'Group' = relationship(
        "Group", uselist=False, cascade="all,delete", overlaps="group")
    directory: 'Directory' = relationship(
        "Directory", uselist=False, cascade="all,delete", overlaps="directory")
    member_group: 'Group' = relationship(
        "Group",
        secondary="Directory",
        primaryjoin="DirectoryMembership.directory_id == Directory.id",
        secondaryjoin="Directory.id == Group.directory_id",
        uselist=False,
        overlaps="directory")


class PolicyMembership(Base):
    """Policy membership - path m2m relationship."""

    __tablename__ = "PolicyMemberships"
    group_id = Column(Integer, ForeignKey("Groups.id"), primary_key=True)
    policy_id = Column(
        Integer, ForeignKey("Policies.id"), primary_key=True)


class PolicyMFAMembership(Base):
    """Policy membership - path m2m relationship."""

    __tablename__ = "PolicyMFAMemberships"
    group_id = Column(Integer, ForeignKey("Groups.id"), primary_key=True)
    policy_id = Column(
        Integer, ForeignKey("Policies.id"), primary_key=True)


class AccessPolicyMembership(Base):
    """Directory - policy m2m relationship."""

    __tablename__ = "AccessPolicyMemberships"
    dir_id = Column(Integer, ForeignKey("Directory.id"), primary_key=True)
    policy_id = Column(
        Integer, ForeignKey("AccessPolicies.id"), primary_key=True)


class GroupAccessPolicyMembership(Base):
    """Directory - policy m2m relationship."""

    __tablename__ = "GroupAccessPolicyMemberships"
    group_id = Column(Integer, ForeignKey("Groups.id"), primary_key=True)
    policy_id = Column(
        Integer, ForeignKey("AccessPolicies.id"), primary_key=True)


class Directory(Base):
    """Chierarcy of catalogue unit."""

    __tablename__ = "Directory"

    id = Column(Integer, primary_key=True)  # noqa: A003

    parent_id = Column(
        'parentId', Integer,
        ForeignKey('Directory.id'), index=True, nullable=True)

    parent: list['Directory'] = relationship(
        lambda: Directory, remote_side=id,
        backref=backref('directories', cascade="all,delete"), uselist=False)

    object_class: str = Column('objectClass', String, nullable=False)
    objectclass: str = synonym('object_class')

    name = Column(String, nullable=False)
    cn: str = synonym('name')

    created_at = Column(
        'whenCreated',
        DateTime(timezone=True),
        server_default=func.now(), nullable=False)
    updated_at = Column(
        'whenChanged',
        DateTime(timezone=True),
        onupdate=func.now(), nullable=True)
    depth = Column(Integer)

    object_sid = Column('objectSid', String)
    objectsid: str = synonym('object_sid')

    password_policy_id = Column(
        Integer, ForeignKey('PasswordPolicies.id'), nullable=True)

    object_guid = Column(
        "objectGUID",
        postgresql.UUID(as_uuid=True),
        default=uuid.uuid4,
        nullable=False)
    objectguid: str = synonym('object_guid')

    path = Column(postgresql.ARRAY(String), nullable=False, index=True)

    attributes: list['Attribute'] = relationship(
        'Attribute', cascade="all,delete")
    group: 'Group' = relationship(
        'Group',
        uselist=False,
        cascade="all,delete",
        overlaps='member_group',
        lazy="selectin",
    )
    user: 'User' = relationship(
        'User',
        uselist=False,
        cascade="all,delete",
        lazy="selectin",
    )
    groups: list['Group'] = relationship(
        "Group",
        secondary=DirectoryMembership.__table__,
        primaryjoin="Directory.id == DirectoryMembership.directory_id",
        secondaryjoin="DirectoryMembership.group_id == Group.id",
        back_populates="members",
        lazy="selectin",
        overlaps="group,directory,member_group",
    )
    access_policies: list['AccessPolicy'] = relationship(
        "AccessPolicy",
        secondary=AccessPolicyMembership.__table__,
        primaryjoin="Directory.id == AccessPolicyMembership.dir_id",
        secondaryjoin="AccessPolicyMembership.policy_id == AccessPolicy.id",
        back_populates="directories",
    )

    __table_args__ = (
        UniqueConstraint(
            'parentId', 'name',
            postgresql_nulls_not_distinct=True,
            name='name_parent_uc'),
    )

    search_fields = {
        'cn': 'cn',
        'name': 'name',
        'objectguid': 'objectGUID',
        'objectsid': 'objectSid',
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
            'organizationalUnit': 'ou',
            'domain': 'dc',
        }.get(self.object_class, 'cn')  # type: ignore

    def get_dn(self, dn: DistinguishedNamePrefix = 'cn') -> str:
        """Get distinguished name."""
        return f"{dn}={self.name}"

    @property
    def is_domain(self) -> bool:
        """Is directory domain."""
        return not self.parent_id and self.object_class == 'domain'

    @property
    def path_dn(self) -> str:
        """Get DN from path."""
        return ','.join(reversed(self.path))  # type: ignore

    def create_path(
        self,
        parent: Optional['Directory'] = None,
        dn: DistinguishedNamePrefix = 'cn',
    ) -> None:
        """Create path from a new directory."""
        pre_path: list[str] = parent.path if parent else []  # type: ignore
        self.path = pre_path + [self.get_dn(dn)]
        self.depth = len(self.path)

    def __str__(self) -> str:
        return f"Directory({self.cn})"

    def __repr__(self) -> str:
        return f"Directory({self.id}:{self.cn})"


@declarative_mixin
class DirectoryReferenceMixin:
    """Mixin with dir id reference."""

    id = Column(Integer, primary_key=True)  # noqa: A003

    @declared_attr
    def directory_id(cls) -> Mapped[int]:  # noqa: N805, D102
        return Column(
            'directoryId', ForeignKey('Directory.id'), nullable=False)

    @declared_attr
    def directory(cls) -> Mapped[Directory]:  # noqa: N805, D102
        return relationship(
            'Directory',
            back_populates=str(cls.__name__).lower(),  # type: ignore
            uselist=False,
            lazy='joined',
        )


class User(DirectoryReferenceMixin, Base):
    """Users data from db."""

    __tablename__ = "Users"

    sam_accout_name = Column(
        'sAMAccountName', String, nullable=False, unique=True)
    user_principal_name: str = Column(
        'userPrincipalName', String, nullable=False, unique=True)

    mail = Column(String(255))
    display_name = Column('displayName', String, nullable=True)
    password = Column(String, nullable=True)

    samaccountname: str = synonym('sam_accout_name')
    userprincipalname: str = synonym('user_principal_name')
    displayname: str = synonym('display_name')
    uid: str = synonym('sam_accout_name')
    accountexpires: str = synonym('account_exp')
    last_logon = Column('lastLogon', DateTime(timezone=True))
    account_exp = Column('accountExpires', DateTime(timezone=True))

    search_fields = {
        'mail': 'mail',
        'samaccountname': 'sAMAccountName',
        'userprincipalname': 'userPrincipalName',
        'displayname': 'displayName',
        'uid': 'uid',
        'accountexpires': 'accountExpires',
    }

    password_history: list[str] = Column(
        MutableList.as_mutable(postgresql.ARRAY(String)),
        server_default="{}",
        nullable=False)

    groups: list['Group'] = relationship(
        'Group',
        secondary=DirectoryMembership.__table__,
        primaryjoin="User.directory_id == DirectoryMembership.directory_id",
        secondaryjoin="DirectoryMembership.group_id == Group.id",
        back_populates='users',
        overlaps="group,groups,directory,member_group",
    )

    def get_upn_prefix(self) -> str:
        """Get userPrincipalName prefix."""
        return self.user_principal_name.split('@')[0]

    def __str__(self) -> str:
        return f"User({self.sam_accout_name})"

    def __repr__(self) -> str:
        return f"User({self.directory_id}:{self.sam_accout_name})"

    def is_expired(self) -> bool:
        """Check AccountExpires."""
        if self.account_exp is None:
            return False

        now = datetime.now(tz=timezone.utc)
        user_account_exp = self.account_exp.astimezone(timezone.utc)

        return True if now > user_account_exp else False

class Group(DirectoryReferenceMixin, Base):
    """Group params."""

    __tablename__ = "Groups"

    id = Column(Integer, primary_key=True)  # noqa: A003
    search_fields: dict[str, str] = {}

    members: list['Directory'] = relationship(
        "Directory",
        secondary=DirectoryMembership.__table__,
        back_populates="groups",
        overlaps="group,groups,directory,member_group",
    )

    parent_groups: list['Group'] = relationship(
        'Group',
        secondary=DirectoryMembership.__table__,
        primaryjoin="Group.directory_id == DirectoryMembership.directory_id",
        secondaryjoin=DirectoryMembership.group_id == id,
        overlaps="group,groups,members,directory,member_group",
    )

    policies: list['NetworkPolicy'] = relationship(
        "NetworkPolicy",
        secondary=PolicyMembership.__table__,
        primaryjoin=id == PolicyMembership.__table__.c.group_id,
        back_populates='groups',
    )

    mfa_policies: list['NetworkPolicy'] = relationship(
        "NetworkPolicy",
        secondary=PolicyMFAMembership.__table__,
        primaryjoin=id == PolicyMFAMembership.__table__.c.group_id,
        back_populates='mfa_groups',
    )

    users: list['User'] = relationship(
        "User",
        secondary=DirectoryMembership.__table__,
        primaryjoin=id == DirectoryMembership.__table__.c.group_id,
        secondaryjoin=DirectoryMembership.directory_id == User.directory_id,
        back_populates='groups',
        overlaps="directory,group,members,parent_groups,member_group,groups",
    )

    access_policies: list['AccessPolicy'] = relationship(
        "AccessPolicy",
        secondary=GroupAccessPolicyMembership.__table__,
        primaryjoin="Group.id == GroupAccessPolicyMembership.group_id",
        secondaryjoin=(
            "GroupAccessPolicyMembership.policy_id == AccessPolicy.id"),
        back_populates="groups",
    )

    def __str__(self) -> str:
        return f"Group({self.id})"

    def __repr__(self) -> str:
        return f"Group({self.id}:{self.directory_id})"


class Attribute(DirectoryReferenceMixin, Base):
    """Attributes data."""

    __tablename__ = "Attributes"
    __table_args__ = (
        CheckConstraint(
            '(value IS NULL) <> (bvalue IS NULL)',
            name='constraint_value_xor_bvalue'),)

    name = Column(String, nullable=False, index=True)
    value = Column(String, nullable=True)
    bvalue = Column(LargeBinary, nullable=True)

    directory: Directory = relationship(
        'Directory', back_populates='attributes', uselist=False)


class MFAFlags(int, enum.Enum):
    """Two-Factor auth action."""

    DISABLED = 0
    ENABLED = 1
    WHITELIST = 2


class NetworkPolicy(Base):
    """Network policy data."""

    __tablename__ = "Policies"

    id = Column(Integer, primary_key=True)  # noqa: A003
    name = Column(String, nullable=False, unique=True)

    raw = Column(postgresql.JSON, nullable=False)
    netmasks = Column(
        postgresql.ARRAY(postgresql.CIDR),
        nullable=False, unique=True, index=True)

    enabled = Column(Boolean, server_default=expression.true(), nullable=False)
    priority = Column(Integer, nullable=False)

    priority_uc = UniqueConstraint(
        priority, name='priority_uc',
        deferrable=True, initially='DEFERRED')

    groups: list['Group'] = relationship(
        "Group",
        secondary=PolicyMembership.__table__,
        back_populates='policies',
    )
    mfa_status: MFAFlags = Column(
        Enum(MFAFlags), server_default='DISABLED', nullable=False)

    mfa_groups: list['Group'] = relationship(
        "Group", secondary=PolicyMFAMembership.__table__,
        back_populates='mfa_policies',
    )


class PasswordPolicy(Base):
    """Password policy."""

    __tablename__ = "PasswordPolicies"

    id = Column(Integer, primary_key=True)  # noqa: A003
    name = Column(
        String(255), nullable=False,
        unique=True, server_default='Default Policy')

    password_history_length = Column(
        Integer, nullable=False, server_default='4')
    maximum_password_age_days = Column(
        Integer, nullable=False, server_default='0')
    minimum_password_age_days = Column(
        Integer, nullable=False, server_default='0')
    minimum_password_length = Column(
        Integer, nullable=False, server_default='7')
    password_must_meet_complexity_requirements = Column(
        Boolean, server_default=expression.true(), nullable=False)


class AccessPolicy(Base):
    """Access policy."""

    __tablename__ = "AccessPolicies"

    id = Column(Integer, primary_key=True)  # noqa: A003
    name = Column(String(255), nullable=False, unique=True)

    can_read = Column(Boolean, nullable=False)
    can_add = Column(Boolean, nullable=False)
    can_modify = Column(Boolean, nullable=False)
    can_delete = Column(Boolean, nullable=False)

    directories: list[Directory] = relationship(
        "Directory",
        secondary=AccessPolicyMembership.__table__,
        order_by="Directory.depth",
        back_populates="access_policies",
    )

    groups: list[Group] = relationship(
        "Group",
        secondary=GroupAccessPolicyMembership.__table__,
        back_populates="access_policies",
    )
