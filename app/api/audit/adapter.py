"""Adapter for audit policies.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import HTTPException, status

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


class AuditPoliciesAdapter:
    """Adapter for audit policies."""

    def __init__(self, audit_service: AuditService) -> None:
        """Initialize the adapter with an audit service."""
        self.audit_service = audit_service

    async def get_policies(self) -> list[AuditPolicySchema]:
        """Get all audit policies."""
        return await self.audit_service.get_policies()

    async def update_policy(
        self,
        policy_id: int,
        policy_data: AuditPolicySchemaRequest,
    ) -> AuditPolicySchema:
        """Update an existing audit policy."""
        try:
            return await self.audit_service.update_policy(
                policy_id,
                policy_data,
            )
        except AuditNotFoundError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            )
        except AuditAlreadyExistsError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e),
            )

    async def get_destinations(self) -> list[AuditDestinationSchema]:
        """Get all audit destinations."""
        return await self.audit_service.get_destinations()

    async def create_destination(
        self,
        destination_data: AuditDestinationSchemaRequest,
    ) -> AuditDestinationSchema:
        """Create a new audit destination."""
        try:
            return await self.audit_service.create_destination(
                destination_data,
            )
        except AuditAlreadyExistsError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e),
            )

    async def update_destination(
        self,
        destination_id: int,
        destination_data: AuditDestinationSchemaRequest,
    ) -> AuditDestinationSchema:
        """Update an existing audit destination."""
        try:
            return await self.audit_service.update_destination(
                destination_id,
                destination_data,
            )
        except AuditNotFoundError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            )
        except AuditAlreadyExistsError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e),
            )

    async def delete_destination(self, destination_id: int) -> None:
        """Delete an audit destination."""
        try:
            await self.audit_service.delete_destination(destination_id)
        except AuditNotFoundError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            )
