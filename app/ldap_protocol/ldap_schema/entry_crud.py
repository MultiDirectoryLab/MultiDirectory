"""Entry utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, select
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
    object_class_names: list[str]

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
    object_class_names: list[str]


class EntryPaginationSchema(BasePaginationSchema[EntrySchema]):
    """Entry Schema with pagination result."""

    items: list[EntrySchema]


async def get_entries_paginator(
    params: PaginationParams,
    session: AsyncSession,
) -> PaginationResult:
    """Retrieve paginated Entries.

    :param PaginationParams params: page_size and page_number.
    :param AsyncSession session: Database session.
    :return PaginationResult: Chunk of entries and metadata.
    """
    return await PaginationResult[Entry].get(
        params=params,
        query=select(Entry).order_by(Entry.id),
        sqla_model=Entry,
        session=session,
    )


async def create_entry(
    name: str,
    object_class_names: list[str],
    is_system: bool,
    session: AsyncSession,
) -> None:
    """Create a new Entry.

    :param str name: Name.
    :param bool is_system: Is system.
    :param list[str] object_class_names: Entry names.
    :param AsyncSession session: Database session.
    :return None.
    """
    entry = Entry(
        name=name,
        object_class_names=object_class_names,
        is_system=is_system,
    )
    session.add(entry)


async def get_entry_by_name(
    entry_name: str,
    session: AsyncSession,
) -> Entry | None:
    """Get single Entry by name.

    :param str entry_name: Entry name.
    :param AsyncSession session: Database session.
    :return Entry | None: Entry.
    """
    return await session.scalar(
        select(Entry)
        .where(Entry.name == entry_name)
    )  # fmt: skip


async def get_entry_by_object_class_names(
    object_class_names: list[str],
    session: AsyncSession,
) -> Entry | None:
    """Get single Entry by object class names.

    :param list[str] object_class_names: object class names.
    :param AsyncSession session: Database session.
    :return Entry | None: Entry.
    """
    result = await session.execute(
        select(Entry)
        .where(
            Entry.object_class_names.contains(object_class_names),
            Entry.object_class_names.contained_by(object_class_names)
        )
    )  # fmt: skip

    return result.scalar_one_or_none()


async def modify_entry(
    entry: Entry,
    new_statement: EntryUpdateSchema,
    session: AsyncSession,
) -> None:
    """Modify Entry.

    :param Entry entry: Entry.
    :param EntryUpdateSchema new_statement: New statement of entry
    :param AsyncSession session: Database session.
    :return None.
    """
    entry.name = new_statement.name
    entry.object_class_names = new_statement.object_class_names

    result = await session.execute(
        select(Directory)
        .where(Directory.entry_id == entry.id)
        .options(selectinload(Directory.attributes))
    )  # fmt: skip

    for directory in result.scalars().all():
        await session.execute(
            delete(Attribute)
            .where(Attribute.directory == directory)
        )  # fmt: skip

        for object_class_name in entry.object_class_names:
            session.add(
                Attribute(
                    directory=directory,
                    value=object_class_name,
                    name="objectClass",
                )
            )


async def delete_entries_by_names(
    entry_names: list[str],
    session: AsyncSession,
) -> None:
    """Delete not system and not used Entry by Names.

    :param list[str] entry_names: Entry names.
    :param AsyncSession session: Database session.
    :return None.
    """
    await session.execute(
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


async def attach_entry_to_directories(session: AsyncSession) -> None:
    """Attach."""
    result = await session.execute(
        select(Directory)
        .where(Directory.entry_id.is_(None))
        .options(
            selectinload(Directory.attributes),
            selectinload(Directory.entry),
        )
    )

    for directory in result.scalars().all():
        await attach_entry_to_directory(
            directory=directory,
            session=session,
        )


async def attach_entry_to_directory(
    directory: Directory,
    session: AsyncSession,
) -> None:
    """Attach."""
    object_class_names = directory.attributes_dict.get(
        "objectClass", []
    ) + directory.attributes_dict.get("objectclass", [])

    entry = await get_entry_by_object_class_names(
        object_class_names,
        session,
    )
    if not entry:
        entry_name = f"{directory.name}_custom_{directory.id}"
        await create_entry(
            name=entry_name,
            object_class_names=object_class_names,
            is_system=True,
            session=session,
        )
        entry = await get_entry_by_name(entry_name, session)

    directory.entry = entry
