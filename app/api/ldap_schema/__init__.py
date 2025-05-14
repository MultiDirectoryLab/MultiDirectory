"""LDAP Schema routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Depends

from api.auth import get_current_user

ldap_schema_router = APIRouter(
    prefix="/schema",
    tags=["Schema"],
    dependencies=[Depends(get_current_user)],
    route_class=DishkaRoute,
)
