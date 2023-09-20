"""Network policies."""

from fastapi import HTTPException, status
from fastapi.params import Depends
from fastapi.routing import APIRouter
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from api.auth import User, get_current_user
from models.database import AsyncSession, get_session
from models.ldap3 import NetworkPolicy

from .schema import Policy, PolicyResponse, PolicyUpdate

network_router = APIRouter()


@network_router.post('/policy', status_code=status.HTTP_201_CREATED)
async def add_network_policy(
    policy: Policy,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> PolicyResponse:
    """Add newtwork."""
    new_policy = NetworkPolicy(
        name=policy.name,
        netmasks=policy.complete_netmasks,
        priority=policy.priority,
        raw=policy.model_dump(mode='json')['netmasks'],
    )

    try:
        session.add(new_policy)
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail='Entry already exists')

    await session.refresh(new_policy)
    return PolicyResponse.model_validate(new_policy)


@network_router.get('/policy')
async def get_network_policies(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[PolicyResponse]:
    """Get network."""
    return [
        PolicyResponse.from_orm(policy)
        for policy in await session.scalars(select(NetworkPolicy))]


@network_router.delete('/policy')
async def delete_network_policy(
    policy_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> bool:
    """Delete network."""
    selected_policy = await session.get(
        NetworkPolicy, policy_id, with_for_update=True)

    if not selected_policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    await session.delete(selected_policy)
    await session.commit()
    return True


@network_router.put('/policy')
async def switch_network_policy(
    policy: PolicyUpdate,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> PolicyResponse:
    """Set state of network."""
    selected_policy = await session.get(
        NetworkPolicy, policy.id, with_for_update=True)

    if not selected_policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    selected_policy.enabled = policy.is_enabled

    if policy.name:
        selected_policy.name = policy.name

    if policy.netmasks:
        selected_policy.netmasks = policy.netmasks

    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail='Entry already exists')

    return PolicyResponse.from_orm(selected_policy)
