"""Access policy management router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from ldap_protocol.policies.access_policy import (
    AccessPolicyPaginationSchema,
    MaterialAccessPolicySchema,
    get_access_policy_paginator,
)
from ldap_protocol.utils.pagination import PaginationParams

access_policy_router = APIRouter(
    prefix="/access_policy",
    tags=["Access Policy"],
    dependencies=[Depends(get_current_user)],
    route_class=DishkaRoute,
)


@access_policy_router.get(
    "/{page_number}",
    response_model=AccessPolicyPaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_access_policies(
    page_number: int,
    session: FromDishka[AsyncSession],
    page_size: int = 20,
) -> AccessPolicyPaginationSchema:
    """Retrieve a list of all AccessPolicies with paginate.

    \f
    :param int page_number: number of page.
    :param FromDishka[AsyncSession] session: Database session.
    :param int page_size: number of items per page.
    :return AccessPolicyPaginationSchema: Paginator.
    """
    params = PaginationParams(
        page_number=page_number,
        page_size=page_size,
    )
    pagination_result = await get_access_policy_paginator(
        params=params,
        session=session,
    )

    items = [
        MaterialAccessPolicySchema.from_db(item)
        for item in pagination_result.items
    ]
    return AccessPolicyPaginationSchema(
        metadata=pagination_result.metadata,
        items=items,
    )
