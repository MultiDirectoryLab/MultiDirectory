"""Network policies."""

from fastapi import HTTPException, Request, status
from fastapi.params import Depends
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRouter
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from api.auth import User, get_current_user
from ldap_protocol.utils import get_base_dn, get_groups, get_path_dn
from models.database import AsyncSession, get_session
from models.ldap3 import Directory, Group, NetworkPolicy

from .schema import (
    Policy,
    PolicyResponse,
    PolicyUpdate,
    SwapRequest,
    SwapResponse,
)
from .utils import check_policy_count

network_router = APIRouter(prefix='/policy')


@network_router.post('', status_code=status.HTTP_201_CREATED)
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
    new_policy = NetworkPolicy(
        name=policy.name,
        netmasks=policy.complete_netmasks,
        priority=policy.priority,
        raw=policy.model_dump(mode='json')['netmasks'],
    )
    group_dns = []

    if policy.groups:
        base_dn = await get_base_dn(session)
        groups = await get_groups(policy.groups, session)
        new_policy.groups = groups
        group_dns = [
            get_path_dn(group.directory.path, base_dn) for group in groups]

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
        groups=group_dns,
    )


@network_router.get('', name='policy')
async def get_network_policies(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[PolicyResponse]:
    """Get network.

    :param User user: requires login, defaults to Depends(get_current_user)
    :return list[PolicyResponse]: all policies
    """
    base_dn = await get_base_dn(session)
    options = selectinload(NetworkPolicy.groups)\
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
            groups=(
                get_path_dn(group.directory.path, base_dn)
                for group in policy.groups),
        )
        for policy in await session.scalars(
            select(NetworkPolicy).options(options)
            .order_by(NetworkPolicy.priority.asc()))]


@network_router.delete(
    '/{policy_id}',
    response_class=RedirectResponse,
    status_code=status.HTTP_303_SEE_OTHER)
async def delete_network_policy(
    policy_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[PolicyResponse]:
    """Delete policy.

    :param int policy_id: id
    :param User user: requires login
    :raises HTTPException: 404
    :raises HTTPException: 422 On last active policy,
        at least 1 should be in database.
    :return bool: status of delete
    """
    policy = await session.get(
        NetworkPolicy, policy_id, with_for_update=True)

    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    await check_policy_count(session)

    async with session.begin_nested():
        await session.delete(policy)
        await session.flush()
        await session.execute((
            update(NetworkPolicy)
            .values({'priority': NetworkPolicy.priority - 1})
            .filter(NetworkPolicy.priority > policy.priority)
        ))
        await session.commit()

    return RedirectResponse(
        request.scope.get('root_path') + network_router.url_path_for('policy'),
        status_code=status.HTTP_303_SEE_OTHER,
        headers=request.headers,
    )


@network_router.patch('/{policy_id}')
async def switch_network_policy(
    policy_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> bool:
    """Switch state of policy.

    :param int policy_id: id
    :param User user: requires login
    :raises HTTPException: 404
    :raises HTTPException: 422 On last active policy,
        at least 1 should be active
    :return bool: status of update
    """
    policy = await session.get(
        NetworkPolicy, policy_id, with_for_update=True)

    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    if policy.enabled:
        await check_policy_count(session)

    policy.enabled = not policy.enabled
    await session.commit()
    return True


@network_router.put('')
async def update_network_policy(
    policy: PolicyUpdate,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> PolicyResponse:
    """Update policy.

    :param PolicyUpdate policy: update request
    :param User user: requires login, defaults to Depends(get_current_user)
    :raises HTTPException: 404 policy not found
    :raises HTTPException: 422 Invalid group DN
    :raises HTTPException: 422 Entry already exists
    :return PolicyResponse: Policy from database
    """
    selected_policy = await session.get(
        NetworkPolicy, policy.id, with_for_update=True,
        options=[selectinload(NetworkPolicy.groups)])

    if not selected_policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    if policy.name:
        selected_policy.name = policy.name

    if policy.netmasks:
        selected_policy.netmasks = policy.complete_netmasks
        selected_policy.raw = policy.model_dump(mode='json')['netmasks']

    if policy.groups is not None and len(policy.groups) > 0:
        base_dn = await get_base_dn(session)
        groups = await get_groups(policy.groups, session)
        policy.groups = [
            get_path_dn(group.directory.path, base_dn) for group in groups]

        selected_policy.groups = groups

    elif policy.groups is not None and len(policy.groups) == 0:
        selected_policy.groups.clear()

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
        groups=policy.groups,
    )


@network_router.post('/swap')
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
        NetworkPolicy, swap.first_policy_id,
        with_for_update=True)
    policy2 = await session.get(
        NetworkPolicy, swap.second_policy_id,
        with_for_update=True)

    if not policy1 or not policy2:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    policy1.priority, policy2.priority = policy2.priority, policy1.priority
    await session.commit()

    return SwapResponse(
        first_policy_id=policy1.id,
        first_policy_priority=policy1.priority,
        second_policy_id=policy2.id,
        second_policy_priority=policy2.priority,
    )
