"""Audit routers.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Depends

from api.auth import get_current_user

audit_router = APIRouter(
    prefix="/audit",
    tags=["Audit policy"],
    dependencies=[Depends(get_current_user)],
    route_class=DishkaRoute,
)
