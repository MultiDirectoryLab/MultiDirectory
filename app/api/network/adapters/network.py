"""Network policy adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import status

from api.base_adapter import BaseAdapter
from api.network.schema import Policy, PolicyResponse
from ldap_protocol.policies.network.dto import NetworkPolicyDTO
from ldap_protocol.policies.network.exceptions import (
    NetworkPolicyAlreadyExistsError,
)
from ldap_protocol.policies.network.use_cases import NetworkPolicyUseCase


class NetworkPolicyFastAPIAdapter(BaseAdapter[NetworkPolicyUseCase]):
    """Network policy adapter."""

    _exceptions_map: dict[type[Exception], int] = {
        NetworkPolicyAlreadyExistsError: status.HTTP_422_UNPROCESSABLE_ENTITY,
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
