"""Password policy views.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Depends

from api.auth import get_current_user
from ldap_protocol.policies.password_policy import (
    PasswordPolicySchema,
    PasswordUseCases,
)

pwd_router = APIRouter(
    prefix="/password-policy",
    dependencies=[Depends(get_current_user)],
    tags=["Password policy"],
    route_class=DishkaRoute,
)


@pwd_router.get("")
async def get_or_create_policy(
    password_use_cases: FromDishka[PasswordUseCases],
) -> PasswordPolicySchema:
    """Get current policy setting."""
    password_policy = await password_use_cases.get_or_create_password_policy()
    return password_policy


@pwd_router.put("")
async def update_policy(
    policy: PasswordPolicySchema,
    password_use_cases: FromDishka[PasswordUseCases],
) -> None:
    """Update current policy setting."""
    await password_use_cases.update_policy(policy)


@pwd_router.delete("")
async def reset_policy(
    password_use_cases: FromDishka[PasswordUseCases],
) -> PasswordPolicySchema:
    """Reset current policy setting."""
    return await password_use_cases.reset_policy()
