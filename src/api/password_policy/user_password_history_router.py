"""User Password history router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka import FromDishka
from fastapi import Body, Depends, status
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.auth.utils import verify_auth
from api.error_routing import (
    ERROR_MAP_TYPE,
    DishkaErrorAwareRoute,
    DomainErrorTranslator,
)
from api.password_policy.adapter import UserPasswordHistoryResetFastAPIAdapter
from api.utils import require_master_db
from application.identity.exceptions import (
    AuthorizationError,
    UserNotFoundError,
)
from enums import DomainCodes

translator = DomainErrorTranslator(DomainCodes.PASSWORD_POLICY)

error_map: ERROR_MAP_TYPE = {
    UserNotFoundError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    AuthorizationError: rule(
        status=status.HTTP_401_UNAUTHORIZED,
        translator=translator,
    ),
}

user_password_history_router = ErrorAwareRouter(
    prefix="/user/password_history",
    dependencies=[Depends(verify_auth), Depends(require_master_db)],
    tags=["User Password history"],
    route_class=DishkaErrorAwareRoute,
)


@user_password_history_router.post("/clear", error_map=error_map)
async def clear(
    identity: Annotated[str, Body(examples=["admin"])],
    adapter: FromDishka[UserPasswordHistoryResetFastAPIAdapter],
) -> None:
    await adapter.clear(identity)
