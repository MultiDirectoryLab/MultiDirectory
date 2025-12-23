"""Password Policy router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from fastapi import Depends, status
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.auth.utils import verify_auth
from api.error_routing import (
    ERROR_MAP_TYPE,
    DishkaErrorAwareRoute,
    DomainErrorTranslator,
)
from api.password_policy.adapter import UserPasswordHistoryResetFastAPIAdapter
from enums import DomainCodes
from ldap_protocol.identity.exceptions import (
    AuthorizationError,
    UserNotFoundError,
)

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
    dependencies=[Depends(verify_auth)],
    tags=["User Password history"],
    route_class=DishkaErrorAwareRoute,
)


@user_password_history_router.post("/clear/{user_name}", error_map=error_map)
async def clear(
    user_name: str,
    adapter: FromDishka[UserPasswordHistoryResetFastAPIAdapter],
) -> None:
    await adapter.clear(user_name)
