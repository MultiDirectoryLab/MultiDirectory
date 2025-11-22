"""Network policies.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from fastapi import Request, status
from fastapi.params import Depends
from fastapi.responses import RedirectResponse
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.auth.utils import verify_auth
from api.network.adapters.network import NetworkPolicyFastAPIAdapter
from enums import ProjectPartCodes
from errors import (
    ERROR_MAP_TYPE,
    BaseErrorTranslator,
    DishkaErrorAwareRoute,
    ErrorStatusCodes,
)
from ldap_protocol.policies.network.exceptions import (
    LastActivePolicyError,
    NetworkPolicyAlreadyExistsError,
    NetworkPolicyNotFoundError,
)

from .schema import (
    Policy,
    PolicyResponse,
    PolicyUpdate,
    SwapRequest,
    SwapResponse,
)


class NetworkPolicyErrorTranslator(BaseErrorTranslator):
    """Network policy error translator."""

    domain_code = ProjectPartCodes.NETWORK


error_map: ERROR_MAP_TYPE = {
    NetworkPolicyAlreadyExistsError: rule(
        status=ErrorStatusCodes.UNPROCESSABLE_ENTITY,
        translator=NetworkPolicyErrorTranslator(),
    ),
    NetworkPolicyNotFoundError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=NetworkPolicyErrorTranslator(),
    ),
    LastActivePolicyError: rule(
        status=ErrorStatusCodes.UNPROCESSABLE_ENTITY,
        translator=NetworkPolicyErrorTranslator(),
    ),
}


network_router = ErrorAwareRouter(
    prefix="/policy",
    tags=["Network policy"],
    route_class=DishkaErrorAwareRoute,
    dependencies=[Depends(verify_auth)],
)


@network_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    error_map=error_map,
)
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


@network_router.get("", name="policy", error_map=error_map)
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
    error_map=error_map,
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


@network_router.patch("/{policy_id}", error_map=error_map)
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


@network_router.put("", error_map=error_map)
async def update_network_policy(
    request: PolicyUpdate,
    adapter: FromDishka[NetworkPolicyFastAPIAdapter],
) -> PolicyResponse:
    """Update network policy.

    \f
    :param PolicyUpdate policy: update request
    :raises HTTPException: 404 policy not found
    :raises HTTPException: 422 Invalid group DN
    :raises HTTPException: 422 Entry already exists
    :return PolicyResponse: Policy from database
    """
    return await adapter.update(request)


@network_router.post("/swap", error_map=error_map)
async def swap_network_policy(
    swap: SwapRequest,
    adapter: FromDishka[NetworkPolicyFastAPIAdapter],
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
    return await adapter.swap_priorities(
        swap.first_policy_id,
        swap.second_policy_id,
    )
