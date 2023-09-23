"""Network policies."""

from fastapi import HTTPException, status
from fastapi.params import Depends
from fastapi.routing import APIRouter
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import make_transient, selectinload

from api.auth import User, get_current_user
from ldap_protocol.utils import get_base_dn, get_group, get_path_dn
from models.database import AsyncSession, get_session
from models.ldap3 import Directory, Group, NetworkPolicy

from .schema import (
    Policy,
    PolicyResponse,
    PolicyUpdate,
    SwapRequest,
    SwapResponse,
)

network_router = APIRouter()


@network_router.post('/policy', status_code=status.HTTP_201_CREATED)
async def add_network_policy(
    policy: Policy,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> PolicyResponse:
    """Add policy.

    :param Policy policy: policy to add
    :param User user: requires login, defaults to Depends(get_current_user)
    :raises HTTPException: 422 invalid group DN
    :raises HTTPException: 422 Entry already exists
    :return PolicyResponse: Ready policy
    """
    group_dir = None
    group = None
    group_dn = None

    try:
        if policy.group:
            group_dir = await get_group(policy.group, session)
            group = group_dir.group
            group_dn = get_path_dn(group_dir.path, await get_base_dn(session))

    except ValueError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid group DN")

    new_policy = NetworkPolicy(
        name=policy.name,
        netmasks=policy.complete_netmasks,
        priority=policy.priority,
        raw=policy.model_dump(mode='json')['netmasks'],
        group=group,
    )

    try:
        session.add(new_policy)
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, 'Entry already exists')

    await session.refresh(new_policy)

    return PolicyResponse(
        id=new_policy.id,
        name=new_policy.name,
        netmasks=new_policy.netmasks,
        raw=new_policy.raw,
        enabled=new_policy.enabled,
        priority=new_policy.priority,
        group=group_dn,
    )


@network_router.get('/policy')
async def get_network_policies(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[PolicyResponse]:
    """Get network.

    :param User user: requires login, defaults to Depends(get_current_user)
    :return list[PolicyResponse]: all policies
    """
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
            select(NetworkPolicy).options(options)
            .order_by(NetworkPolicy.priority.asc()))]


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
    """Set state of network.

    :param PolicyUpdate policy: update request
    :param User user: requires login, defaults to Depends(get_current_user)
    :raises HTTPException: 404 policy not found
    :raises HTTPException: 422 Invalid group DN
    :raises HTTPException: 422 Entry already exists
    :return PolicyResponse: Policy from database
    """
    selected_policy = await session.get(
        NetworkPolicy, policy.id, with_for_update=True)

    if not selected_policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    selected_policy.enabled = policy.is_enabled

    if policy.name:
        selected_policy.name = policy.name

    if policy.netmasks:
        selected_policy.netmasks = policy.complete_netmasks
        selected_policy.raw = policy.netmasks

    if policy.group:
        try:
            group_dir = await get_group(policy.group, session)
        except ValueError:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid group DN")

        policy.group = get_path_dn(group_dir.path, await get_base_dn(session))
        selected_policy.group = group_dir.group

    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, 'Entry already exists')

    return PolicyResponse(
        id=selected_policy.id,
        name=selected_policy.name,
        netmasks=selected_policy.netmasks,
        raw=selected_policy.raw,
        enabled=selected_policy.enabled,
        priority=selected_policy.priority,
        group=policy.group,
    )


@network_router.post('/policy/swap')
async def swap_network_policy(
    swap: SwapRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> SwapResponse:
    """Swap priorities.

    :param int first_policy_id: policy to swap
    :param int second_policy_id: policy to swap
    :param User user: needs login, defaults to Depends(get_current_user)
    :raises HTTPException: 404
    :return SwapResponse: policy new priorities
    """
    policy1 = await session.get(
        NetworkPolicy, swap.first_policy_id, with_for_update=True)
    policy2 = await session.get(
        NetworkPolicy, swap.second_policy_id, with_for_update=True)

    if not policy1 or not policy2:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    await session.delete(policy1)
    await session.commit()

    policy1.priority, policy2.priority = policy2.priority, policy1.priority

    make_transient(policy1)
    session.add(policy1)
    await session.commit()

    return SwapResponse(
        first_policy_id=policy1.id,
        first_policy_priority=policy1.priority,
        second_policy_id=policy2.id,
        second_policy_priority=policy2.priority,
    )
