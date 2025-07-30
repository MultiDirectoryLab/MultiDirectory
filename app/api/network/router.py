"""Network policies.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import HTTPException, Request, status
from fastapi.params import Depends
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRouter
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth import get_current_user
from ldap_protocol.utils.queries import get_groups
from models import Group, NetworkPolicy

from .schema import (
    Policy,
    PolicyResponse,
    PolicyUpdate,
    SwapRequest,
    SwapResponse,
)
from .utils import check_policy_count

network_router = APIRouter(
    prefix="/policy",
    tags=["Network policy"],
    route_class=DishkaRoute,
    dependencies=[Depends(get_current_user)],
)


@network_router.post("", status_code=status.HTTP_201_CREATED)
async def add_network_policy(
    policy: Policy,
    session: FromDishka[AsyncSession],
) -> PolicyResponse:
    """Add policy.

    \f
    :param Policy policy: policy to add
    :raises HTTPException: 422 invalid group DN
    :raises HTTPException: 422 Entry already exists
    :return PolicyResponse: Ready policy
    """
    new_policy = NetworkPolicy(
        name=policy.name,
        netmasks=policy.complete_netmasks,
        priority=policy.priority,
        raw=policy.model_dump(mode="json")["netmasks"],
        mfa_status=policy.mfa_status,
        is_http=policy.is_http,
        is_ldap=policy.is_ldap,
        is_kerberos=policy.is_kerberos,
        bypass_no_connection=policy.bypass_no_connection,
        bypass_service_failure=policy.bypass_service_failure,
    )
    group_dns = []
    mfa_group_dns = []

    if policy.groups:
        groups = await get_groups(policy.groups, session)
        new_policy.groups = groups
        group_dns = [group.directory.path_dn for group in groups]

    if policy.mfa_groups:
        mfa_groups = await get_groups(policy.mfa_groups, session)
        new_policy.mfa_groups = mfa_groups
        mfa_group_dns = [group.directory.path_dn for group in mfa_groups]

    try:
        session.add(new_policy)
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Entry already exists",
        )

    await session.refresh(new_policy)

    return PolicyResponse(
        id=new_policy.id,
        name=new_policy.name,
        netmasks=new_policy.netmasks,
        raw=new_policy.raw,
        enabled=new_policy.enabled,
        priority=new_policy.priority,
        groups=group_dns,
        mfa_status=new_policy.mfa_status,
        mfa_groups=mfa_group_dns,
        is_http=new_policy.is_http,
        is_ldap=new_policy.is_ldap,
        is_kerberos=new_policy.is_kerberos,
        bypass_no_connection=new_policy.bypass_no_connection,
        bypass_service_failure=new_policy.bypass_service_failure,
    )


@network_router.get("", name="policy")
async def get_list_network_policies(
    session: FromDishka[AsyncSession],
) -> list[PolicyResponse]:
    """Get network.

    \f
    :return list[PolicyResponse]: all policies
    """
    groups = selectinload(NetworkPolicy.groups).selectinload(Group.directory)
    mfa_groups = selectinload(NetworkPolicy.mfa_groups).selectinload(
        Group.directory,
    )

    return [
        PolicyResponse(
            id=policy.id,
            name=policy.name,
            netmasks=policy.netmasks,
            raw=policy.raw,
            enabled=policy.enabled,
            priority=policy.priority,
            groups=(group.directory.path_dn for group in policy.groups),
            mfa_status=policy.mfa_status,
            mfa_groups=(
                group.directory.path_dn for group in policy.mfa_groups
            ),
            is_http=policy.is_http,
            is_ldap=policy.is_ldap,
            is_kerberos=policy.is_kerberos,
            bypass_no_connection=policy.bypass_no_connection,
            bypass_service_failure=policy.bypass_service_failure,
        )
        for policy in await session.scalars(
            select(NetworkPolicy)
            .options(groups, mfa_groups)
            .order_by(NetworkPolicy.priority.asc()),
        )
    ]


@network_router.delete(
    "/{policy_id}",
    response_class=RedirectResponse,
    status_code=status.HTTP_303_SEE_OTHER,
)
async def delete_network_policy(
    policy_id: int,
    request: Request,
    session: FromDishka[AsyncSession],
) -> list[PolicyResponse]:
    """Delete policy.

    \f
    :param int policy_id: id
    :param User user: requires login
    :raises HTTPException: 404
    :raises HTTPException: 422 On last active policy,
        at least 1 should be in database.
    :return bool: status of delete
    """
    policy = await session.get(NetworkPolicy, policy_id, with_for_update=True)

    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    await check_policy_count(session)

    async with session.begin_nested():
        await session.delete(policy)
        await session.flush()
        await session.execute(
            (
                update(NetworkPolicy)
                .values({"priority": NetworkPolicy.priority - 1})
                .filter(NetworkPolicy.priority > policy.priority)
            ),
        )
        await session.commit()

    return RedirectResponse(
        request.url_for("policy"),
        status_code=status.HTTP_303_SEE_OTHER,
        headers=request.headers,
    )  # type: ignore


@network_router.patch("/{policy_id}")
async def switch_network_policy(
    policy_id: int,
    session: FromDishka[AsyncSession],
) -> bool:
    """Switch state of policy.

    - **policy_id**: int, policy to switch
    \f
    :param int policy_id: id
    :param User user: requires login
    :raises HTTPException: 404
    :raises HTTPException: 422 On last active policy,
        at least 1 should be active
    :return bool: status of update
    """
    policy = await session.get(NetworkPolicy, policy_id, with_for_update=True)

    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    if policy.enabled:
        await check_policy_count(session)

    policy.enabled = not policy.enabled
    await session.commit()
    return True


@network_router.put("")
async def update_network_policy(
    request: PolicyUpdate,
    session: FromDishka[AsyncSession],
) -> PolicyResponse:
    """Update network policy.

    \f
    :param PolicyUpdate policy: update request
    :raises HTTPException: 404 policy not found
    :raises HTTPException: 422 Invalid group DN
    :raises HTTPException: 422 Entry already exists
    :return PolicyResponse: Policy from database
    """
    selected_policy = await session.get(
        NetworkPolicy,
        request.id,
        with_for_update=True,
        options=[
            selectinload(NetworkPolicy.groups),
            selectinload(NetworkPolicy.mfa_groups),
        ],
    )

    if not selected_policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    for field in PolicyUpdate.fields_map:
        value = getattr(request, field)
        if value is not None:
            setattr(selected_policy, field, value)

    if request.netmasks:
        selected_policy.netmasks = request.complete_netmasks
        selected_policy.raw = request.model_dump(mode="json")["netmasks"]

    groups_path_dn = []
    if request.groups is not None and len(request.groups) > 0:
        groups = await get_groups(request.groups, session)
        selected_policy.groups = groups

        groups_path_dn = [group.directory.path_dn for group in groups]

    elif request.groups is not None and len(request.groups) == 0:
        selected_policy.groups.clear()

    mfa_groups_path_dn = []
    if request.mfa_groups is not None and len(request.mfa_groups) > 0:
        mfa_groups = await get_groups(request.mfa_groups, session)
        selected_policy.mfa_groups = mfa_groups

        mfa_groups_path_dn = [group.directory.path_dn for group in mfa_groups]

    elif request.mfa_groups is not None and len(request.mfa_groups) == 0:
        selected_policy.mfa_groups.clear()

    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Entry already exists",
        )

    return PolicyResponse(
        id=selected_policy.id,
        name=selected_policy.name,
        netmasks=selected_policy.netmasks,
        raw=selected_policy.raw,
        enabled=selected_policy.enabled,
        priority=selected_policy.priority,
        groups=groups_path_dn,
        mfa_status=selected_policy.mfa_status,
        mfa_groups=mfa_groups_path_dn,
        is_http=selected_policy.is_http,
        is_ldap=selected_policy.is_ldap,
        is_kerberos=selected_policy.is_kerberos,
        bypass_no_connection=selected_policy.bypass_no_connection,
        bypass_service_failure=selected_policy.bypass_service_failure,
    )


@network_router.post("/swap")
async def swap_network_policy(
    swap: SwapRequest,
    session: FromDishka[AsyncSession],
) -> SwapResponse:
    """Swap priorities for policy.

    - **first_policy_id**: policy to swap
    - **second_policy_id**: policy to swap
    \f
    :param int first_policy_id: policy to swap
    :param int second_policy_id: policy to swap
    :raises HTTPException: 404
    :return SwapResponse: policy new priorities
    """
    policy1 = await session.get(
        NetworkPolicy,
        swap.first_policy_id,
        with_for_update=True,
    )
    policy2 = await session.get(
        NetworkPolicy,
        swap.second_policy_id,
        with_for_update=True,
    )

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
