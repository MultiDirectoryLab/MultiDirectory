"""Network policy adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from fastapi import Request, status
from fastapi.responses import RedirectResponse

from api.base_adapter import BaseAdapter
from api.network.schema import Policy, PolicyResponse
from ldap_protocol.policies.network.dto import NetworkPolicyDTO
from ldap_protocol.policies.network.exceptions import (
    LastActivePolicyError,
    NetworkPolicyAlreadyExistsError,
    NetworkPolicyNotFoundError,
)
from ldap_protocol.policies.network.use_cases import NetworkPolicyUseCase


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
        return PolicyResponse(
            id=policy_dto.id,
            name=policy_dto.name,
            netmasks=policy_dto.netmasks,
            raw=policy_dto.raw,
            enabled=policy_dto.enabled,
            priority=policy_dto.priority,
            groups=policy_dto.groups,
            mfa_groups=policy_dto.mfa_groups,
            is_http=policy_dto.is_http,
            is_ldap=policy_dto.is_ldap,
            is_kerberos=policy_dto.is_kerberos,
            bypass_no_connection=policy_dto.bypass_no_connection,
            bypass_service_failure=policy_dto.bypass_service_failure,
            mfa_status=policy_dto.mfa_status,
        )

    async def get_list_policies(self) -> list[PolicyResponse]:
        """Get list of network policies."""
        policy_dtos = await self._service.get_list_policies()
        return [
            PolicyResponse(
                id=policy_dto.id,
                name=policy_dto.name,
                netmasks=policy_dto.netmasks,
                raw=policy_dto.raw,
                enabled=policy_dto.enabled,
                priority=policy_dto.priority,
                groups=policy_dto.groups,
                mfa_groups=policy_dto.mfa_groups,
                is_http=policy_dto.is_http,
                is_ldap=policy_dto.is_ldap,
                is_kerberos=policy_dto.is_kerberos,
                bypass_no_connection=policy_dto.bypass_no_connection,
                bypass_service_failure=policy_dto.bypass_service_failure,
                mfa_status=policy_dto.mfa_status,
            )
            for policy_dto in policy_dtos
        ]

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
        return await self._service.switch_network_policy(_id)
