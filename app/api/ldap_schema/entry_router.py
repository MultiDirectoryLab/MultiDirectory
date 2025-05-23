"""Entry management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Body, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema.object_class_router import ldap_schema_router
from ldap_protocol.ldap_schema.entry_crud import (
    EntryPaginationSchema,
    EntrySchema,
    EntryUpdateSchema,
    create_entry,
    delete_entries_by_names,
    get_entries_paginator,
    get_entry_by_name,
    modify_entry,
)
from ldap_protocol.ldap_schema.object_class_crud import (
    count_exists_object_class_by_names,
)
from ldap_protocol.utils.pagination import PaginationParams

_DEFAULT_ENTRY_IS_SYSTEM = False


@ldap_schema_router.post(
    "/entry",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_entry(
    request_data: EntrySchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new Entry.

    \f
    :param EntrySchema request_data: Data for creating Entry.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_400_BAD_REQUEST: If Object Classes not found.
    :return None.
    """
    count_exists_object_classes = await count_exists_object_class_by_names(
        request_data.object_class_names,
        session,
    )

    if count_exists_object_classes != len(request_data.object_class_names):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Object Classes not found.",
        )

    await create_entry(
        name=request_data.name,
        is_system=_DEFAULT_ENTRY_IS_SYSTEM,
        object_class_names=request_data.object_class_names,
        session=session,
    )
    await session.commit()


@ldap_schema_router.get(
    "/entry/{entry_name}",
    response_model=EntrySchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_entry(
    entry_name: str,
    session: FromDishka[AsyncSession],
) -> EntrySchema:
    """Retrieve a one entry.

    \f
    :param str entry_name: name of the entry.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If entry not found.
    :return EntrySchema: One entry Schemas.
    """
    entry = await get_entry_by_name(
        entry_name,
        session,
    )

    if not entry:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Entry not found.",
        )

    return EntrySchema.from_db(entry)


@ldap_schema_router.get(
    "/entries/{page_number}",
    response_model=EntryPaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_entries_with_pagination(
    page_number: int,
    session: FromDishka[AsyncSession],
    page_size: int = 25,
) -> EntryPaginationSchema:
    """Retrieve a list of all entries with paginate.

    \f
    :param int page_number: number of page.
    :param FromDishka[AsyncSession] session: Database session.
    :param int page_size: number of items per page.
    :return EntryPaginationSchema: Paginator.
    """
    params = PaginationParams(
        page_number=page_number,
        page_size=page_size,
    )

    pagination_result = await get_entries_paginator(
        params=params, session=session
    )

    items = [EntrySchema.from_db(item) for item in pagination_result.items]
    return EntryPaginationSchema(
        metadata=pagination_result.metadata,
        items=items,
    )


@ldap_schema_router.patch(
    "/entry/{entry_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_entry(
    entry_name: str,
    request_data: EntryUpdateSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an Entry.

    \f
    :param str entry_name: Name of the Entry for modifying.
    :param EntryUpdateSchema request_data: Changed data.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If nothing to delete.
    :raise HTTP_400_BAD_REQUEST: If Entry is system->cannot be changed
    :raise HTTP_400_BAD_REQUEST: If Object Classes not found.
    :return None.
    """
    entry = await get_entry_by_name(entry_name, session)
    if not entry:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Entry not found.",
        )

    if entry.is_system:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "System Entry cannot be modified.",
        )

    count_exists_object_classes = await count_exists_object_class_by_names(
        request_data.object_class_names,
        session,
    )
    if count_exists_object_classes != len(request_data.object_class_names):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Object Classes not found.",
        )

    await modify_entry(
        entry=entry,
        new_statement=request_data,
        session=session,
    )
    await session.commit()


@ldap_schema_router.post(
    "/entry/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_entries(
    entry_names: Annotated[list[str], Body(embed=True)],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete Entries by their names.

    \f
    :param list[str] entry_names: List of Entries names.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_400_BAD_REQUEST: If nothing to delete.
    :return None: None
    """
    if not entry_names:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Entries not found.",
        )

    await delete_entries_by_names(entry_names, session)
    await session.commit()
