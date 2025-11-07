"""Network policy adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv4Network
from typing import Literal

from adaptix import P
from adaptix.conversion import get_converter, link_function
from fastapi import Request, status
from fastapi.responses import RedirectResponse

from api.base_adapter import BaseAdapter
from api.network.schema import (
    Policy,
    PolicyResponse,
    PolicyUpdate,
    SwapResponse,
)
from ldap_protocol.policies.network.dto import (
    NetworkPolicyDTO,
    NetworkPolicyUpdateDTO,
)
from ldap_protocol.policies.network.exceptions import (
    LastActivePolicyError,
    NetworkPolicyAlreadyExistsError,
    NetworkPolicyNotFoundError,
)
from ldap_protocol.policies.network.use_cases import NetworkPolicyUseCase


def _convert_netmasks(
    dto: NetworkPolicyDTO[int],
) -> list[IPv4Network]:
    """Convert list of IPv4Network | IPv4Address to list of IPv4Network."""
    return [
        IPv4Network(item) if isinstance(item, IPv4Address) else item
        for item in dto.netmasks
    ]


def _convert_raw(dto: NetworkPolicyDTO[int]) -> list[str | dict]:
    """Convert dict | list to list[str | dict]."""
    raw = dto.raw
    if isinstance(raw, dict):
        return [] if not raw else [raw]
    return raw


_convert_dto_to_schema = get_converter(
    NetworkPolicyDTO[int],
    PolicyResponse,
    recipe=[
        link_function(
            _convert_netmasks,
            P[PolicyResponse].netmasks,
        ),
        link_function(
            _convert_raw,
            P[PolicyResponse].raw,
        ),
    ],
)


class NetworkPolicyFastAPIAdapter(BaseAdapter[NetworkPolicyUseCase]):
    """Network policy adapter."""

    _exceptions_map: dict[type[Exception], int] = {
        NetworkPolicyAlreadyExistsError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        LastActivePolicyError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        NetworkPolicyNotFoundError: status.HTTP_404_NOT_FOUND,
    }

    async def create(self, policy: Policy) -> PolicyResponse:
        """Create network policy."""
        policy_dto = await self._service.create(
            NetworkPolicyDTO(
                id=None,
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
                groups=policy.groups,
                mfa_groups=policy.mfa_groups,
            ),
        )
        return _convert_dto_to_schema(policy_dto)

    async def get_list_policies(self) -> list[PolicyResponse]:
        """Get list of network policies."""
        dtos = await self._service.get_list_policies()
        return list(map(_convert_dto_to_schema, dtos))

    async def delete(self, request: Request, _id: int) -> RedirectResponse:
        """Delete network policy."""
        await self._service.delete(_id)
        return RedirectResponse(
            request.url_for("policy"),
            status_code=status.HTTP_303_SEE_OTHER,
            headers=request.headers,
        )

    async def switch_network_policy(self, _id: int) -> Literal[True]:
        """Switch network policy."""
        await self._service.switch_network_policy(_id)
        return True

    async def update(self, model: PolicyUpdate) -> PolicyResponse:
        """Update network policy."""
        policy_dto = await self._service.update(
            NetworkPolicyUpdateDTO(
                id=model.id,
                name=model.name,
                netmasks=model.complete_netmasks if model.netmasks else None,
                mfa_status=model.mfa_status,
                is_http=model.is_http,
                is_ldap=model.is_ldap,
                is_kerberos=model.is_kerberos,
                groups=model.groups,
                mfa_groups=model.mfa_groups,
                bypass_no_connection=model.bypass_no_connection,
                bypass_service_failure=model.bypass_service_failure,
                raw=model.model_dump(mode="json")["netmasks"]
                if model.netmasks
                else None,
            ),
        )

        return _convert_dto_to_schema(policy_dto)

    async def swap_priorities(self, id1: int, id2: int) -> SwapResponse:
        """Swap priorities for network policies."""
        swap_dto = await self._service.swap_priorities(id1, id2)
        return SwapResponse(
            first_policy_id=id1,
            first_policy_priority=swap_dto.priority1,
            second_policy_id=id2,
            second_policy_priority=swap_dto.priority2,
        )
