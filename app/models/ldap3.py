"""MultiDirectory LDAP models."""

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
)

from .database import Base


class CatalogueSetting(Base):
    """Catalogue params unit."""

    __tablename__ = "Settings"

    id = Column(Integer, primary_key=True)  # noqa: A003
    name = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False)


class Directory(Base):
    """Chierarcy of catalogue unit."""

    __tablename__ = "Directory"

    id = Column(Integer, primary_key=True)  # noqa: A003

    parent_id = Column(
        'parentId', Integer,
        ForeignKey('Directory.id'), index=True, nullable=True)

    parent: list['Directory'] = relationship(
        lambda: Directory, remote_side=id, backref='directories')

    object_class = Column('objectClass', String, nullable=False)

    name = Column(String, nullable=False)

    created_at = Column(
        'whenCreated',
        DateTime(timezone=True),
        server_default=func.now(), nullable=False)
    updated_at = Column(
        'whenChanged',
        DateTime(timezone=True),
        onupdate=func.now(), nullable=True)

    path: 'Path' = relationship("Path", back_populates="endpoint", lazy="joined", uselist=False)

    __table_args__ = (
        UniqueConstraint('parentId', 'name', name='name_parent_uc'),
    )

    def get_dn(self):
        """Get distinguished name."""
        return {
            'organizationUnit': 'OU',
            'domain': 'DC',
        }.get(self.object_class, 'CN')


@declarative_mixin
class DirectoryReferenceMixin:
    """Mixin with dir id reference."""

    id = Column(Integer, primary_key=True)  # noqa: A003

    @declared_attr
    def directory_id(cls) -> Mapped[int]:  # noqa: N805, D102
        return Column(
            'directoryId', ForeignKey('Directory.id'), nullable=False)

    @declared_attr
    def dirctory(cls) -> Mapped[Directory]:  # noqa: N805, D102
        return relationship(
            'Directory', backref=f'{str(cls.__name__).lower()}s', lazy='joined')


class User(DirectoryReferenceMixin, Base):
    """Users data."""

    __tablename__ = "Users"

    sam_accout_name = Column(
        'sAMAccountName', String, nullable=False, unique=True)
    user_principal_name = Column(
        'userPrincipalName', String, nullable=False, unique=True)

    display_name = Column('displayName', String, nullable=True)
    password = Column(String, nullable=True)


class Group(DirectoryReferenceMixin, Base):
    """Group params."""

    __tablename__ = "Groups"


class Computer(DirectoryReferenceMixin, Base):
    """Computers data."""

    __tablename__ = "Computers"


class Attrubute(DirectoryReferenceMixin, Base):
    """Attributes data."""

    __tablename__ = "Attributes"

    name = Column(String, nullable=False)
    value = Column(String, nullable=False)


class DirectoryPath(Base):
    """Directory - path m2m relationship."""

    __tablename__ = "DirectoryPaths"
    dir_id = Column(Integer, ForeignKey("Directory.id"), primary_key=True)
    path_id = Column(Integer, ForeignKey("Paths.id"), primary_key=True)


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
        # order_by="DirectoryPaths.position",
        # collection_class=ordering_list('DirectoryPaths.position'),
        backref="paths",
    )
