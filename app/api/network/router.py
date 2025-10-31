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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth import get_current_user
from api.network.adapters.network import NetworkPolicyFastAPIAdapter
from entities import NetworkPolicy
from ldap_protocol.utils.queries import get_groups
from repo.pg.tables import queryable_attr as qa

from .schema import (
    Policy,
    PolicyResponse,
    PolicyUpdate,
    SwapRequest,
    SwapResponse,
)

network_router = APIRouter(
    prefix="/policy",
    tags=["Network policy"],
    route_class=DishkaRoute,
    dependencies=[Depends(get_current_user)],
)


@network_router.post("", status_code=status.HTTP_201_CREATED)
async def add_network_policy(
    policy: Policy,
    adapter: FromDishka[NetworkPolicyFastAPIAdapter],
) -> PolicyResponse:
    """Add policy.

    \f
    :param Policy policy: policy to add
    :raises HTTPException: 422 invalid group DN
    :raises HTTPException: 422 Entry already exists
    :return PolicyResponse: Ready policy
    """
    return await adapter.create(policy)


@network_router.get("", name="policy")
async def get_list_network_policies(
    adapter: FromDishka[NetworkPolicyFastAPIAdapter],
) -> list[PolicyResponse]:
    """Get network.

    \f
    :return list[PolicyResponse]: all policies
    """
    return await adapter.get_list_policies()


@network_router.delete(
    "/{policy_id}",
    response_class=RedirectResponse,
    status_code=status.HTTP_303_SEE_OTHER,
)
async def delete_network_policy(
    policy_id: int,
    request: Request,
    adapter: FromDishka[NetworkPolicyFastAPIAdapter],
) -> list[PolicyResponse]:
    """Delete policy.

    \f
    :param int policy_id: id
    :param Request request: request
    :param NetworkPolicyFastAPIAdapter adapter: adapter
    :return RedirectResponse: redirect response
    """
    return await adapter.delete(request, policy_id)  # type: ignore


@network_router.patch("/{policy_id}")
async def switch_network_policy(
    policy_id: int,
    adapter: FromDishka[NetworkPolicyFastAPIAdapter],
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
    return await adapter.switch_network_policy(policy_id)


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
            selectinload(qa(NetworkPolicy.groups)),
            selectinload(qa(NetworkPolicy.mfa_groups)),
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
