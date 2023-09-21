"""Network policies."""

from fastapi import HTTPException, status
from fastapi.params import Depends
from fastapi.routing import APIRouter
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from api.auth import User, get_current_user
from ldap_protocol.utils import get_base_dn, get_group, get_path_dn
from models.database import AsyncSession, get_session
from models.ldap3 import Directory, Group, NetworkPolicy

from .schema import Policy, PolicyResponse, PolicyUpdate

network_router = APIRouter()


@network_router.post('/policy', status_code=status.HTTP_201_CREATED)
async def add_network_policy(
    policy: Policy,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> PolicyResponse:
    """Add newtwork."""
    group_dir = None

    try:
        if policy.group:
            group_dir = await get_group(policy.group, session)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid group DN")

    new_policy = NetworkPolicy(
        name=policy.name,
        netmasks=policy.complete_netmasks,
        priority=policy.priority,
        raw=policy.model_dump(mode='json')['netmasks'],
        group=group_dir.group,
    )

    try:
        session.add(new_policy)
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail='Entry already exists')

    await session.refresh(new_policy)

    group = get_path_dn(group_dir.path, await get_base_dn(session))

    return PolicyResponse(
        id=new_policy.id,
        name=new_policy.name,
        netmasks=new_policy.netmasks,
        raw=new_policy.raw,
        enabled=new_policy.enabled,
        priority=new_policy.priority,
        group=group,
    )


@network_router.get('/policy')
async def get_network_policies(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[PolicyResponse]:
    """Get network."""
    base_dn = await get_base_dn(session)
    options = selectinload(NetworkPolicy.group)\
        .selectinload(Group.directory)\
        .selectinload(Directory.path)

    return [
        PolicyResponse(
            id=policy.id,
            name=policy.name,
            netmasks=policy.netmasks,
            raw=policy.raw,
            enabled=policy.enabled,
            priority=policy.priority,
            group=(
                get_path_dn(policy.group.directory.path, base_dn)
                if policy.group else None),
        )
        for policy in await session.scalars(
            select(NetworkPolicy).options(options))]


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
