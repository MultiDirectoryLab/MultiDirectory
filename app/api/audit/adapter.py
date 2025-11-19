"""Adapter for audit policies.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ParamSpec, TypeVar

from fastapi import status

from api.base_adapter import BaseAdapter
from ldap_protocol.policies.audit.dataclasses import (
    AuditDestinationDTO,
    AuditPolicyDTO,
)
from ldap_protocol.policies.audit.exception import (
    AuditAlreadyExistsError,
    AuditNotFoundError,
)
from ldap_protocol.policies.audit.schemas import (
    AuditDestinationResponse,
    AuditDestinationSchemaRequest,
    AuditPolicyResponse,
    AuditPolicySchemaRequest,
)
from ldap_protocol.policies.audit.service import AuditService

P = ParamSpec("P")
R = TypeVar("R")


class AuditPoliciesAdapter(BaseAdapter[AuditService]):
    """Adapter for audit policies."""

    _exceptions_map: dict[type[Exception], int] = {
        AuditNotFoundError: status.HTTP_404_NOT_FOUND,
        AuditAlreadyExistsError: status.HTTP_409_CONFLICT,
    }

    async def get_policies(self) -> list[AuditPolicyResponse]:
        """Get all audit policies."""
        return [
            AuditPolicyResponse(
                id=policy.get_id(),
                name=policy.name,
                is_enabled=policy.is_enabled,
                severity=policy.severity.name.lower(),
            )
            for policy in await self._service.get_policies()
        ]

    async def update_policy(
        self,
        policy_id: int,
        policy_data: AuditPolicySchemaRequest,
    ) -> None:
        """Update an existing audit policy."""
        policy_dto = AuditPolicyDTO(**policy_data.model_dump())
        return await self._service.update_policy(
            policy_id,
            policy_dto,
        )

    async def get_destinations(self) -> list[AuditDestinationResponse]:
        """Get all audit destinations."""
        return [
            AuditDestinationResponse(
                id=destination.id,  # type: ignore
                name=destination.name,
                service_type=destination.service_type.name.lower(),
                host=destination.host,
                port=destination.port,
                protocol=destination.protocol.name.lower(),
                is_enabled=destination.is_enabled,
            )
            for destination in await self._service.get_destinations()
        ]

    async def create_destination(
        self,
        destination_data: AuditDestinationSchemaRequest,
    ) -> None:
        """Create a new audit destination."""
        destination_dto = AuditDestinationDTO(**destination_data.model_dump())
        return await self._service.create_destination(destination_dto)

    async def update_destination(
        self,
        destination_id: int,
        destination_data: AuditDestinationSchemaRequest,
    ) -> None:
        """Update an existing audit destination."""
        destination_dto = AuditDestinationDTO(**destination_data.model_dump())
        return await self._service.update_destination(
            destination_id,
            destination_dto,
        )

    async def delete_destination(self, destination_id: int) -> None:
        """Delete an audit destination."""
        await self._service.delete_destination(destination_id)
