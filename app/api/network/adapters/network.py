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
        policy_entity, groups, mfa_groups = await self._service.create(
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
            id=policy_entity.id,
            name=policy_entity.name,
            netmasks=policy_entity.netmasks,
            raw=policy_entity.raw,
            enabled=policy_entity.enabled,
            priority=policy_entity.priority,
            groups=[group.directory.path_dn for group in groups],
            mfa_groups=[group.directory.path_dn for group in mfa_groups],
            is_http=policy_entity.is_http,
            is_ldap=policy_entity.is_ldap,
            is_kerberos=policy_entity.is_kerberos,
            bypass_no_connection=policy_entity.bypass_no_connection,
            bypass_service_failure=policy_entity.bypass_service_failure,
            mfa_status=policy_entity.mfa_status,
        )
