"""MultiDirectory LDAP models."""

import enum
from typing import Literal, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import (
    Mapped,
    backref,
    declarative_mixin,
    declared_attr,
    relationship,
    synonym,
)
from sqlalchemy.sql import expression

from .database import Base

DistinguishedNamePrefix = Literal['cn', 'ou', 'dc']

UniqueConstraint.argument_for("postgresql", 'nulls_not_distinct', None)


@compiles(UniqueConstraint, "postgresql")
def compile_create_uc(create, compiler, **kw):
    """Add NULLS NOT DISTINCT if its in args."""
    stmt = compiler.visit_unique_constraint(create, **kw)
    postgresql_opts = create.dialect_options["postgresql"]

    if postgresql_opts.get("nulls_not_distinct"):
        return stmt.rstrip().replace("UNIQUE (", "UNIQUE NULLS NOT DISTINCT (")
    return stmt


class CatalogueSetting(Base):
    """Catalogue params unit."""

    __tablename__ = "Settings"

    id = Column(Integer, primary_key=True)  # noqa: A003
    name = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False)


class GroupMembership(Base):
    """Group membership - path m2m relationship."""

    __tablename__ = "GroupMemberships"
    group_id = Column(Integer, ForeignKey("Groups.id"), primary_key=True)
    group_child_id = Column(Integer, ForeignKey("Groups.id"), primary_key=True)


class UserMembership(Base):
    """User membership - path m2m relationship."""

    __tablename__ = "UserMemberships"
    group_id = Column(Integer, ForeignKey("Groups.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("Users.id"), primary_key=True)


class DirectoryPath(Base):
    """Directory - path m2m relationship."""

    __tablename__ = "DirectoryPaths"
    dir_id = Column(Integer, ForeignKey("Directory.id"), primary_key=True)
    path_id = Column(Integer, ForeignKey("Paths.id"), primary_key=True)


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

    path: 'Path' = relationship(
        "Path", back_populates="endpoint",
        lazy="joined", uselist=False,
        cascade="all,delete",
    )

    paths: list['Path'] = relationship(
        "Path",
        secondary=DirectoryPath.__table__,
        back_populates="directories",
    )

    attributes: list['Attribute'] = relationship(
        'Attribute', cascade="all,delete")
    group: 'Group' = relationship('Group', uselist=False, cascade="all,delete")
    user: 'User' = relationship('User', uselist=False, cascade="all,delete")
    computer: 'Computer' = relationship(
        'Computer', uselist=False, cascade="all,delete")

    __table_args__ = (
        UniqueConstraint(
            'parentId', 'name',
            postgresql_nulls_not_distinct=True,
            name='name_parent_uc'),
    )

    search_fields = {
        'cn': 'cn',
        'name': 'name',
    }

    ro_fields = {
        "uid",
        "whenCreated",
        "lastLogon",
    }

    def get_dn_prefix(self) -> str:
        """Get distinguished name prefix."""
        return {
            'organizationalUnit': 'ou',
            'domain': 'dc',
        }.get(self.object_class, 'cn')  # type: ignore

    def get_dn(self, dn: DistinguishedNamePrefix = 'cn') -> str:
        """Get distinguished name."""
        return f"{dn}={self.name}".lower()

    def create_path(
        self,
        parent: Optional['Directory'] = None,
        dn: DistinguishedNamePrefix = 'cn',
    ) -> 'Path':
        """Create Path from a new directory."""
        pre_path: list[str] =\
            parent.path.path if parent else []  # type: ignore
        return Path(
            path=pre_path + [self.get_dn(dn)],
            endpoint=self)


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
            back_populates=str(cls.__name__).lower(),
            uselist=False,
            lazy='joined',
        )


class User(DirectoryReferenceMixin, Base):
    """Users data."""

    __tablename__ = "Users"

    sam_accout_name = Column(
        'sAMAccountName', String, nullable=False, unique=True)
    user_principal_name = Column(
        'userPrincipalName', String, nullable=False, unique=True)

    mail = Column(String(255))
    display_name = Column('displayName', String, nullable=True)
    password = Column(String, nullable=True)

    samaccountname: str = synonym('sam_accout_name')
    userprincipalname: str = synonym('user_principal_name')
    displayname: str = synonym('display_name')
    uid: str = synonym('sam_accout_name')

    search_fields = {
        'mail': 'mail',
        'samaccountname': 'sAMAccountName',
        'userprincipalname': 'userPrincipalName',
        'displayname': 'displayName',
        'uid': 'uid',
    }

    groups: list['Group'] = relationship(
        "Group",
        secondary=UserMembership.__table__,
        back_populates='users',
    )


class Group(DirectoryReferenceMixin, Base):
    """Group params."""

    __tablename__ = "Groups"

    id = Column(Integer, primary_key=True)  # noqa: A003
    search_fields = {}

    child_groups: list['Group'] = relationship(
        "Group",
        secondary=GroupMembership.__table__,
        primaryjoin=id == GroupMembership.__table__.c.group_id,
        secondaryjoin=id == GroupMembership.__table__.c.group_child_id,
        back_populates='parent_groups')

    parent_groups: list['Group'] = relationship(
        "Group",
        secondary=GroupMembership.__table__,
        primaryjoin=id == GroupMembership.__table__.c.group_child_id,
        secondaryjoin=id == GroupMembership.__table__.c.group_id,
        back_populates='child_groups')

    users: list['User'] = relationship(
        "User",
        secondary=UserMembership.__table__,
        primaryjoin=id == UserMembership.__table__.c.group_id,
        back_populates='groups',
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


class Computer(DirectoryReferenceMixin, Base):
    """Computers data."""

    __tablename__ = "Computers"


class Attribute(DirectoryReferenceMixin, Base):
    """Attributes data."""

    __tablename__ = "Attributes"

    name = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False)

    directory: Directory = relationship(
        'Directory', back_populates='attributes', uselist=False)


class Path(Base):
    """Directory path data."""

    __tablename__ = "Paths"

    id = Column(Integer, primary_key=True)  # noqa: A003
    path = Column(postgresql.ARRAY(String), nullable=False, index=True)

    endpoint_id = Column(Integer, ForeignKey('Directory.id'), nullable=False)
    endpoint: Directory = relationship(
        "Directory", back_populates="path", lazy="joined")

    directories: list[Directory] = relationship(
        "Directory",
        secondary=DirectoryPath.__table__,
        order_by="Directory.depth",
        back_populates="paths",
    )


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
