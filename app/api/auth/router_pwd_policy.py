"""Password policy views.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from api.auth import get_current_user
from ldap_protocol.password_policy import PasswordPolicySchema
from models.database import AsyncSession, get_session

pwd_router = APIRouter(
    prefix='/password-policy',
    dependencies=[Depends(get_current_user)],
    tags=['Password policy'],
)


@pwd_router.post('', status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy: PasswordPolicySchema,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PasswordPolicySchema:
    """Create current policy setting."""
    return await policy.create_policy_settings(session)


@pwd_router.get('')
async def get_policy(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PasswordPolicySchema:
    """Get current policy setting."""
    return await PasswordPolicySchema.get_policy_settings(session)


@pwd_router.put('')
async def update_policy(
    policy: PasswordPolicySchema,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PasswordPolicySchema:
    """Update current policy setting."""
    await policy.update_policy_settings(session)
    return policy


@pwd_router.delete('')
async def reset_policy(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PasswordPolicySchema:
    """Reset current policy setting."""
    return await PasswordPolicySchema.delete_policy_settings(session)
