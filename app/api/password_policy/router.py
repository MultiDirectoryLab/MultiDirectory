"""Password policy views.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Depends, status

from api.auth import get_current_user
from api.password_policy.adapter import PasswordPoliciesAdapter
from api.password_policy.schemas import (
    PasswordPolicyResponseDTO,
    PasswordPolicySchema,
)

pwd_router = APIRouter(
    prefix="/password-policy",
    dependencies=[Depends(get_current_user)],
    tags=["Password policy"],
    route_class=DishkaRoute,
)


@pwd_router.get("")
async def get_policy(
    adapter: FromDishka[PasswordPoliciesAdapter],
) -> PasswordPolicyResponseDTO:
    """Get current policy setting."""
    return await adapter.get_policy()


@pwd_router.post("", status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy: PasswordPolicySchema,
    adapter: FromDishka[PasswordPoliciesAdapter],
) -> None:
    """Create current policy setting."""
    await adapter.create_policy(policy)


@pwd_router.put("")
async def update_policy(
    policy: PasswordPolicySchema,
    adapter: FromDishka[PasswordPoliciesAdapter],
) -> None:
    """Update current policy setting."""
    await adapter.update_policy(policy)


@pwd_router.delete("")
async def reset_policy(
    adapter: FromDishka[PasswordPoliciesAdapter],
) -> None:
    """Reset current policy setting."""
    await adapter.reset_policy()
