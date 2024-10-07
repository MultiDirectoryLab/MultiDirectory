"""Password policy views.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.password_policy import PasswordPolicySchema

pwd_router = APIRouter(
    prefix="/password-policy",
    dependencies=[Depends(get_current_user)],
    tags=["Password policy"],
)


@pwd_router.post("", status_code=status.HTTP_201_CREATED)
@inject
async def create_policy(
    policy: PasswordPolicySchema,
    session: FromDishka[AsyncSession],
    kadmin: FromDishka[AbstractKadmin],
) -> PasswordPolicySchema:
    """Create current policy setting."""
    return await policy.create_policy_settings(session, kadmin)


@pwd_router.get("")
@inject
async def get_policy(
    session: FromDishka[AsyncSession],
    kadmin: FromDishka[AbstractKadmin],
) -> PasswordPolicySchema:
    """Get current policy setting."""
    return await PasswordPolicySchema.get_policy_settings(session, kadmin)


@pwd_router.put("")
@inject
async def update_policy(
    policy: PasswordPolicySchema,
    session: FromDishka[AsyncSession],
    kadmin: FromDishka[AbstractKadmin],
) -> PasswordPolicySchema:
    """Update current policy setting."""
    await policy.update_policy_settings(session, kadmin)
    return policy


@pwd_router.delete("")
@inject
async def reset_policy(
    session: FromDishka[AsyncSession],
    kadmin: FromDishka[AbstractKadmin],
) -> PasswordPolicySchema:
    """Reset current policy setting."""
    return await PasswordPolicySchema.delete_policy_settings(session, kadmin)
