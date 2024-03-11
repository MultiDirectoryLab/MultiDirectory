"""Password policy views."""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from api.auth import get_current_user
from ldap_protocol.password_policy import PasswordPolicySchema
from models.database import AsyncSession, get_session

pwd_router = APIRouter(prefix='/password-policy')


@pwd_router.post(
    '', dependencies=[Depends(get_current_user)],
    status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy: PasswordPolicySchema,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PasswordPolicySchema:
    """Create current policy setting."""
    return await policy.create_policy_settings(session)


@pwd_router.get('', dependencies=[Depends(get_current_user)])
async def get_policy(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PasswordPolicySchema:
    """Get current policy setting."""
    return await PasswordPolicySchema.get_policy_settings(session)


@pwd_router.put('', dependencies=[Depends(get_current_user)])
async def update_policy(
    policy: PasswordPolicySchema,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PasswordPolicySchema:
    """Update current policy setting."""
    await policy.update_policy_settings(session)
    return policy


@pwd_router.delete('', dependencies=[Depends(get_current_user)])
async def reset_policy(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PasswordPolicySchema:
    """Reset current policy setting."""
    return await PasswordPolicySchema.delete_policy_settings(session)
