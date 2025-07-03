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

from api.auth import get_current_user
from api.utils import NetworkPolicyService
from api.utils.exceptions import NotFoundError, PolicyError

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
    network_policy_service: FromDishka[NetworkPolicyService],
) -> PolicyResponse:
    """Add policy.

    \f
    :param Policy policy: policy to add
    :raises HTTPException: 422 invalid group DN
    :raises HTTPException: 422 Entry already exists
    :return PolicyResponse: Ready policy
    """
    try:
        return await network_policy_service.add_policy(policy)
    except PolicyError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )


@network_router.get("", name="policy")
async def get_list_network_policies(
    network_policy_service: FromDishka[NetworkPolicyService],
) -> list[PolicyResponse]:
    """Get network.

    \f
    :return list[PolicyResponse]: all policies
    """
    return await network_policy_service.get_policies()


@network_router.delete(
    "/{policy_id}",
    response_class=RedirectResponse,
    status_code=status.HTTP_303_SEE_OTHER,
)
async def delete_network_policy(
    policy_id: int,
    request: Request,
    network_policy_service: FromDishka[NetworkPolicyService],
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
    try:
        return await network_policy_service.delete_policy(policy_id, request)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PolicyError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )


@network_router.patch("/{policy_id}")
async def switch_network_policy(
    policy_id: int,
    network_policy_service: FromDishka[NetworkPolicyService],
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
    try:
        return await network_policy_service.switch_policy(policy_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PolicyError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )


@network_router.put("")
async def update_network_policy(
    request: PolicyUpdate,
    network_policy_service: FromDishka[NetworkPolicyService],
) -> PolicyResponse:
    """Update network policy.

    \f
    :param PolicyUpdate policy: update request
    :raises HTTPException: 404 policy not found
    :raises HTTPException: 422 Invalid group DN
    :raises HTTPException: 422 Entry already exists
    :return PolicyResponse: Policy from database
    """
    try:
        return await network_policy_service.update_policy(request)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PolicyError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )


@network_router.post("/swap")
async def swap_network_policy(
    swap: SwapRequest,
    network_policy_service: FromDishka[NetworkPolicyService],
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
    try:
        return await network_policy_service.swap_policy(swap)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PolicyError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
