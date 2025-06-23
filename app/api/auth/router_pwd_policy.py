"""Password policy views.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from ldap_protocol.policies.password_policy import PasswordPolicySchema

pwd_router = APIRouter(
    prefix="/password-policy",
    dependencies=[Depends(get_current_user)],
    tags=["Password policy"],
    route_class=DishkaRoute,
)


@pwd_router.post("", status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy: PasswordPolicySchema,
    session: FromDishka[AsyncSession],
) -> PasswordPolicySchema:
    """Create current policy setting.

    Args:
        policy (PasswordPolicySchema): Password policy schema to create.
        session (AsyncSession): Database session.

    Returns:
        PasswordPolicySchema: Created password policy schema.
    """
    return await policy.create_policy_settings(session)


@pwd_router.get("")
async def get_policy(
    session: FromDishka[AsyncSession],
) -> PasswordPolicySchema:
    """Get current policy setting.

    Returns:
        PasswordPolicySchema: Current password policy schema.
    """
    return await PasswordPolicySchema.get_policy_settings(session)


@pwd_router.put("")
async def update_policy(
    policy: PasswordPolicySchema,
    session: FromDishka[AsyncSession],
) -> PasswordPolicySchema:
    """Update current policy setting.

    Args:
        policy (PasswordPolicySchema): Password policy schema to update.
        session (AsyncSession): Database session.

    Returns:
        PasswordPolicySchema: Updated password policy schema.
    """
    await policy.update_policy_settings(session)
    return policy


@pwd_router.delete("")
async def reset_policy(
    session: FromDishka[AsyncSession],
) -> PasswordPolicySchema:
    """Reset current policy setting.

    Returns:
        PasswordPolicySchema: Reset password policy schema.
    """
    return await PasswordPolicySchema.delete_policy_settings(session)
