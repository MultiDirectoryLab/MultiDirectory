"""Entry management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import FromDishka
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema import LimitedListType
from api.ldap_schema.object_class_router import ldap_schema_router
from ldap_protocol.ldap_schema.entry_crud import (
    EntryDAO,
    EntryPaginationSchema,
    EntrySchema,
    EntryUpdateSchema,
)
from ldap_protocol.ldap_schema.object_class_crud import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams

_DEFAULT_ENTRY_IS_SYSTEM = False


@ldap_schema_router.post(
    "/entry",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_entry(
    request_data: EntrySchema,
    entry_manager: FromDishka[EntryDAO],
    object_class_manager: FromDishka[ObjectClassDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new Entry.

    \f
    :param EntrySchema request_data: Data for creating Entry.
    :param FromDishka[EntryDAO] entry_manager: Entry manager.
    :param FromDishka[ObjectClassDAO] object_class_manager: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_400_BAD_REQUEST: If Object Classes not found.
    :return None.
    """
    if not await object_class_manager.is_all_object_classes_exists(
        request_data.object_class_names
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Object Classes not found.",
        )

    await entry_manager.create_entry(
        name=request_data.name,
        is_system=_DEFAULT_ENTRY_IS_SYSTEM,
        object_class_names=request_data.object_class_names,
    )
    await session.commit()


@ldap_schema_router.get(
    "/entry/{entry_name}",
    response_model=EntrySchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_entry(
    entry_name: str,
    entry_manager: FromDishka[EntryDAO],
) -> EntrySchema:
    """Retrieve a one entry.

    \f
    :param str entry_name: name of the entry.
    :param FromDishka[EntryDAO] entry_manager: Entry manager.
    :raise HTTP_404_NOT_FOUND: If entry not found.
    :return EntrySchema: One entry Schemas.
    """
    entry = await entry_manager.get_entry_by_name(entry_name)

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
    entry_manager: FromDishka[EntryDAO],
    page_size: int = 25,
) -> EntryPaginationSchema:
    """Retrieve a list of all entries with paginate.

    \f
    :param int page_number: number of page.
    :param FromDishka[EntryDAO] entry_manager: Entry manager.
    :param int page_size: number of items per page.
    :return EntryPaginationSchema: Paginator.
    """
    params = PaginationParams(
        page_number=page_number,
        page_size=page_size,
    )

    pagination_result = await entry_manager.get_entries_paginator(
        params=params
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
    entry_manager: FromDishka[EntryDAO],
    object_class_manager: FromDishka[ObjectClassDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an Entry.

    \f
    :param str entry_name: Name of the Entry for modifying.
    :param EntryUpdateSchema request_data: Changed data.
    :param FromDishka[EntryDAO] entry_manager: Entry manager.
    :param FromDishka[ObjectClassDAO] object_class_manager: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If nothing to delete.
    :raise HTTP_400_BAD_REQUEST: If Object Classes not found.
    :return None.
    """
    entry = await entry_manager.get_entry_by_name(entry_name)
    if not entry:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Entry not found.",
        )

    if not await object_class_manager.is_all_object_classes_exists(
        request_data.object_class_names
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Object Classes not found.",
        )

    await entry_manager.modify_entry(
        entry=entry,
        new_statement=request_data,
    )
    await session.commit()


@ldap_schema_router.post(
    "/entry/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_entries(
    entry_names: LimitedListType,
    entry_manager: FromDishka[EntryDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete Entries by their names.

    \f
    :param list[str] entry_names: List of Entries names.
    :param FromDishka[EntryDAO] entry_manager: Entry manager.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_400_BAD_REQUEST: If nothing to delete.
    :return None: None
    """
    await entry_manager.delete_entries_by_names(entry_names)
    await session.commit()
