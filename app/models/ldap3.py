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

    __tablename__ = "Directories"

    id = Column(Integer, primary_key=True)  # noqa: A003

    parent_id = Column(
        'parentId', Integer,
        ForeignKey('Directories.id'), index=True, nullable=True)

    parent: list['Directory'] = relationship(
        "Directory", remote_side=[id], backref='directories')

    object_class = Column('objectClass', String, nullable=False)

    name = Column(String, nullable=False)

    created_at = Column(
        'whenCreated',
        DateTime(timezone=True),
        server_default=func.now(), nullable=False)
    updated_at = Column(
        'whenChanged',
        DateTime(timezone=True),
        onupdate=func.now(), nullable=False)

    users: list['User'] = relationship("User")

    __table_args__ = (
        UniqueConstraint('parentId', 'name', name='name_parent_uc'),
    )


@declarative_mixin
class DirectoryReferenceMixin:
    """Mixin with dir id reference."""

    id = Column(Integer, primary_key=True)  # noqa: A003

    @declared_attr
    def directory_id(cls) -> Mapped[int]:  # noqa: N805, D102
        return Column(
            'directoryId', ForeignKey('Directories.id'), nullable=False)

    @declared_attr
    def dirctory(cls) -> Mapped[Directory]:  # noqa: N805, D102
        return relationship('Directory', back_populates=f'{str(cls).lower()}s')


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
