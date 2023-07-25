"""MultiDirectory LDAP models."""

from typing import Optional, Literal

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import (
    Mapped,
    declarative_mixin,
    declared_attr,
    relationship,
    synonym,
)

from .database import Base

DistinguishedNamePrefix = Literal['cn', 'ou', 'dc']


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


class Directory(Base):
    """Chierarcy of catalogue unit."""

    __tablename__ = "Directory"

    id = Column(Integer, primary_key=True)  # noqa: A003

    parent_id = Column(
        'parentId', Integer,
        ForeignKey('Directory.id'), index=True, nullable=True)

    parent: list['Directory'] = relationship(
        lambda: Directory, remote_side=id,
        backref='directories', uselist=False)

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
        cascade="all,delete",
    )

    attributes: list['Attribute'] = relationship(
        'Attribute', cascade="all,delete")
    group: 'Group' = relationship('Group', uselist=False, cascade="all,delete")
    user: 'User' = relationship('User', uselist=False, cascade="all,delete")
    computer: 'Computer' = relationship(
        'Computer', uselist=False, cascade="all,delete")

    __table_args__ = (
        UniqueConstraint('parentId', 'name', name='name_parent_uc'),
    )

    search_fields = {
        'cn': 'cn',
        'name': 'name',
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

    search_fields = {
        'mail': 'mail',
        'samaccountname': 'sAMAccountName',
        'userprincipalname': 'userPrincipalName',
        'displayname': 'displayName',
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


class Computer(DirectoryReferenceMixin, Base):
    """Computers data."""

    __tablename__ = "Computers"


class Attribute(DirectoryReferenceMixin, Base):
    """Attributes data."""

    __tablename__ = "Attributes"

    name = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False, index=True)

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
