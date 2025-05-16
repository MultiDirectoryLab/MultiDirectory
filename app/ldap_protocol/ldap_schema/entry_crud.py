"""Entry utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.object_class_crud import (
    get_object_classes_by_names,
)
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult
from models import Entry


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


async def get_entries_paginator(
    params: PaginationParams,
    session: AsyncSession,
) -> PaginationResult:
    """Retrieve paginated Entries.

    :param PaginationParams params: page_size and page_number.
    :param AsyncSession session: Database session.
    :return Paginator: Paginated result with entry and metadata.
    """
    return await PaginationResult.get(
        params=params,
        query=select(Entry).order_by(Entry.id),
        sqla_model=Entry,
        schema_model=EntrySchema,
        session=session,
    )


class EntryUpdateSchema(BaseModel):
    """Entry Schema for modify/update."""

    name: str
    object_class_names: list[str]


async def create_entry(
    name: str,
    is_system: bool,
    object_class_names: list[str],
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
        is_system=is_system,
        object_classes=await get_object_classes_by_names(
            object_class_names,
            session,
        ),
    )
    session.add(entry)
    await session.commit()


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

    entry.object_classes.clear()
    entry.object_classes.extend(
        await get_object_classes_by_names(
            new_statement.object_class_names,
            session,
        ),
    )

    await session.commit()


async def delete_entries_by_names(
    entry_names: list[str],
    session: AsyncSession,
) -> None:
    """Delete not system Entry by Names.

    :param list[str] entry_names: Entry names.
    :param AsyncSession session: Database session.
    :return None.
    """
    await session.execute(
        delete(Entry)
        .where(
            Entry.name.in_(entry_names),
            Entry.is_system.is_(False),
        ),
    )  # fmt: skip
    await session.commit()
