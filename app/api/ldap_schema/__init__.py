"""LDAP Schema routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from annotated_types import Len
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Body, Depends

from api.auth import get_current_user

LimitedListType = Annotated[
    list[str],
    Len(min_length=1, max_length=10000),
    Body(embed=True),
]

ldap_schema_router = APIRouter(
    prefix="/schema",
    tags=["Schema"],
    dependencies=[Depends(get_current_user)],
    route_class=DishkaRoute,
)
