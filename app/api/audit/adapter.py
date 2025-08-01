"""Adapter for audit policies.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict
from typing import Awaitable, Callable, ParamSpec, TypeVar

from fastapi import HTTPException, status

from ldap_protocol.policies.audit.dataclasses import (
    AuditDestinationDTO,
    AuditPolicyDTO,
)
from ldap_protocol.policies.audit.exception import (
    AuditAlreadyExistsError,
    AuditNotFoundError,
)
from ldap_protocol.policies.audit.schemas import (
    AuditDestinationSchema,
    AuditDestinationSchemaRequest,
    AuditPolicySchema,
    AuditPolicySchemaRequest,
)
from ldap_protocol.policies.audit.service import AuditService

P = ParamSpec("P")
R = TypeVar("R")


class AuditPoliciesAdapter:
    """Adapter for audit policies."""

    def __init__(self, audit_service: AuditService) -> None:
        """Initialize the adapter with an audit service."""
        self.audit_service = audit_service

    async def _sc(
        self,
        func: Callable[P, Awaitable[R]],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        """Convert Kerberos exceptions to HTTPException.

        :raises HTTPException: on Kerberos errors
        :return: Result of the function call.
        """
        try:
            return await func(*args, **kwargs)
        except AuditNotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
        except AuditAlreadyExistsError:
            raise HTTPException(status.HTTP_409_CONFLICT)

    async def get_policies(self) -> list[AuditPolicySchema]:
        """Get all audit policies."""
        return [
            AuditPolicySchema.model_validate(asdict(policy))
            for policy in await self.audit_service.get_policies()
        ]

    async def update_policy(
        self,
        policy_id: int,
        policy_data: AuditPolicySchemaRequest,
    ) -> None:
        """Update an existing audit policy."""
        policy_dto = AuditPolicyDTO(**policy_data.model_dump())
        return await self._sc(
            self.audit_service.update_policy,
            policy_id,
            policy_dto,
        )

    async def get_destinations(self) -> list[AuditDestinationSchema]:
        """Get all audit destinations."""
        return [
            AuditDestinationSchema.model_validate(asdict(destination))
            for destination in await self.audit_service.get_destinations()
        ]

    async def create_destination(
        self,
        destination_data: AuditDestinationSchemaRequest,
    ) -> None:
        """Create a new audit destination."""
        destination_dto = AuditDestinationDTO(**destination_data.model_dump())
        return await self._sc(
            self.audit_service.create_destination,
            destination_dto,
        )

    async def update_destination(
        self,
        destination_id: int,
        destination_data: AuditDestinationSchemaRequest,
    ) -> None:
        """Update an existing audit destination."""
        destination_dto = AuditDestinationDTO(**destination_data.model_dump())
        return await self._sc(
            self.audit_service.update_destination,
            destination_id,
            destination_dto,
        )

    async def delete_destination(self, destination_id: int) -> None:
        """Delete an audit destination."""
        await self._sc(
            self.audit_service.delete_destination,
            destination_id,
        )
