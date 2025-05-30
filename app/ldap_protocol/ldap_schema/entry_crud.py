"""Entry utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable

from pydantic import BaseModel, Field
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    PaginationParams,
    PaginationResult,
)
from models import Attribute, Directory, Entry


class EntrySchema(BaseModel):
    """Entry Schema."""

    name: str
    is_system: bool
    object_class_names: list[str] = Field([], min_length=1, max_length=10000)

    @classmethod
    def from_db(cls, entry: Entry) -> "EntrySchema":
        """Create an instance of Entry Schema from database."""
        return cls(
            name=entry.name,
            is_system=entry.is_system,
            object_class_names=entry.object_class_names,
        )


class EntryUpdateSchema(BaseModel):
    """Entry Schema for modify/update."""

    name: str
    object_class_names: list[str] = Field([], min_length=1, max_length=10000)


class EntryPaginationSchema(BasePaginationSchema[EntrySchema]):
    """Entry Schema with pagination result."""

    items: list[EntrySchema]


class EntryDAO:
    """Entry manager."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize EntryDAO with a database session."""
        self._session = session

    async def get_entries_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Entries.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of entries and metadata.
        """
        return await PaginationResult[Entry].get(
            params=params,
            query=select(Entry).order_by(Entry.id),
            sqla_model=Entry,
            session=self._session,
        )

    async def create_entry(
        self,
        name: str,
        object_class_names: Iterable[str],
        is_system: bool,
    ) -> None:
        """Create a new Entry.

        :param str name: Name.
        :param Iterable[str] object_class_names: Object Class names.
        :param bool is_system: Is system.
        :return None.
        """
        entry = Entry(
            name=name,
            object_class_names=object_class_names,
            is_system=is_system,
        )
        self._session.add(entry)

    async def get_entry_by_name(
        self,
        entry_name: str,
    ) -> Entry | None:
        """Get single Entry by name.

        :param str entry_name: Entry name.
        :return Entry | None: Instance of Entry.
        """
        return await self._session.scalar(
            select(Entry)
            .where(Entry.name == entry_name)
        )  # fmt: skip

    async def get_entry_by_object_class_names(
        self,
        object_class_names: Iterable[str],
    ) -> Entry | None:
        """Get single Entry by object class names.

        :param Iterable[str] object_class_names: object class names.
        :return Entry | None: Entry.
        """
        result = await self._session.execute(
            select(Entry)
            .where(
                Entry.object_class_names.contains(object_class_names),
                Entry.object_class_names.contained_by(object_class_names)
            )
        )  # fmt: skip

        return result.scalar_one_or_none()

    async def modify_entry(
        self,
        entry: Entry,
        new_statement: EntryUpdateSchema,
    ) -> None:
        """Modify Entry.

        :param Entry entry: Entry.
        :param EntryUpdateSchema new_statement: New statement of entry
        :return None.
        """
        entry.name = new_statement.name
        entry.object_class_names = new_statement.object_class_names

        result = await self._session.execute(
            select(Directory)
            .where(Directory.entry_id == entry.id)
            .options(selectinload(Directory.attributes))
        )  # fmt: skip

        for directory in result.scalars():
            await self._session.execute(
                delete(Attribute)
                .where(
                    Attribute.directory == directory,
                    or_(
                        Attribute.name == "objectclass",
                        Attribute.name == "objectClass"
                    ),
                )
            )  # fmt: skip

            for object_class_name in entry.object_class_names:
                self._session.add(
                    Attribute(
                        directory=directory,
                        value=object_class_name,
                        name="objectClass",
                    )
                )

    async def delete_entries_by_names(
        self,
        entry_names: list[str],
    ) -> None:
        """Delete not system and not used Entry by Names.

        :param list[str] entry_names: Entry names.
        :return None.
        """
        await self._session.execute(
            delete(Entry)
            .where(
                Entry.name.in_(entry_names),
                Entry.is_system.is_(False),
                Entry.id.notin_(
                    select(Directory.entry_id)
                    .where(Directory.entry_id.isnot(None))
                ),
            ),
        )  # fmt: skip

    async def attach_entry_to_directories(self) -> None:
        """Find all directories without an entry and attach an entry to them.

        :return None.
        """
        result = await self._session.execute(
            select(Directory)
            .where(Directory.entry_id.is_(None))
            .options(
                selectinload(Directory.attributes),
                selectinload(Directory.entry),
            )
        )

        for directory in result.scalars():
            await self.attach_entry_to_directory(
                directory=directory,
                is_system_entry=False,
            )

        return None

    async def attach_entry_to_directory(
        self,
        directory: Directory,
        is_system_entry: bool,
    ) -> None:
        """Try to find the Entry, attach this Entry to the Directory.

        :param Directory directory: Directory to attach entry.
        :param bool is_system_entry: Is system entry.
        :return None.
        """
        object_class_names = directory.object_class_names_set

        entry = await self.get_entry_by_object_class_names(object_class_names)
        if not entry:
            entry_name = Entry.generate_entry_name(directory=directory)
            await self.create_entry(
                name=entry_name,
                object_class_names=object_class_names,
                is_system=is_system_entry,
            )
            await self._session.flush()
            entry = await self.get_entry_by_name(entry_name)

        directory.entry = entry
