"""Audit policies service module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.exc import IntegrityError

from .destination_dao import AuditDestinationDAO
from .exception import AuditAlreadyExistsError
from .policies_dao import AuditPoliciesDAO
from .schemas import (
    AuditDestinationSchema,
    AuditDestinationSchemaRequest,
    AuditPolicySchema,
    AuditPolicySchemaRequest,
)


class AuditService:
    """Audit service class for managing audit policies."""

    def __init__(
        self,
        policy_dao: AuditPoliciesDAO,
        destination_dao: AuditDestinationDAO,
    ) -> None:
        """Initialize AuditService with a policy DAO and a destination DAO."""
        self._policy_dao = policy_dao
        self._destination_dao = destination_dao

    async def get_policies(self) -> list[AuditPolicySchema]:
        """Get all audit policies."""
        return [
            AuditPolicySchema.model_validate(policy.__dict__)
            for policy in await self._policy_dao.get_policies()
        ]

    async def update_policy(
        self,
        policy_id: int,
        policy: AuditPolicySchemaRequest,
    ) -> AuditPolicySchema:
        """Update an existing audit policy.

        Args:
            policy_id (int): The ID of the policy to update.
            policy (AuditPolicySchemaRequest): The new policy data.

        Raises:
            AuditNotFoundError: If the policy with the given ID does not exist.
            AuditAlreadyExistsError: If the policy already exists.

        """
        existing_policy = await self._policy_dao.get_policy_by_id(policy_id)
        try:
            await self._policy_dao.update_policy(
                existing_policy,
                policy.id,
                policy.name,
                policy.is_enabled,
            )
        except IntegrityError:
            raise AuditAlreadyExistsError("Audit policy already exists")

        new_policy = await self._policy_dao.get_policy_by_id(policy.id)
        return AuditPolicySchema.model_validate(new_policy.__dict__)

    async def get_destinations(self) -> list[AuditDestinationSchema]:
        """Get all audit destinations."""
        return [
            AuditDestinationSchema.model_validate(destination.__dict__)
            for destination in await self._destination_dao.get_destinations()
        ]

    async def create_destination(
        self,
        destination: AuditDestinationSchemaRequest,
    ) -> AuditDestinationSchema:
        """Create a new audit destination.

        Args:
            destination (AuditDestinationSchema): Destination data to create.

        Raises:
            AuditAlreadyExistsError: If the destination already exists.

        """
        try:
            created_destination = (
                await self._destination_dao.create_destination(
                    destination.name,
                    destination.service_type,
                    destination.host,
                    destination.port,
                    destination.protocol,
                    destination.is_enabled,
                )
            )
        except IntegrityError:
            raise AuditAlreadyExistsError("Audit destination already exists")

        return AuditDestinationSchema.model_validate(
            created_destination.__dict__
        )

    async def update_destination(
        self,
        destination_id: int,
        destination: AuditDestinationSchemaRequest,
    ) -> AuditDestinationSchema:
        """Update an existing audit destination.

        Args:
            destination_id (int): The ID of the destination to update.
            destination (AuditDestinationSchemaRequest): New destination data.

        Raises:
            AuditNotFoundError: If the destination with ID does not exist.
            AuditAlreadyExistsError: If the destination already exists.

        """
        existing_destination = (
            await self._destination_dao.get_destination_by_id(destination_id)
        )
        try:
            await self._destination_dao.update_destination(
                existing_destination,
                destination.name,
                destination.service_type,
                destination.host,
                destination.port,
                destination.protocol,
                destination.is_enabled,
            )
        except IntegrityError:
            raise AuditAlreadyExistsError("Audit destination already exists")

        updated_destination = (
            await self._destination_dao.get_destination_by_id(
                existing_destination.id
            )
        )
        return AuditDestinationSchema.model_validate(
            updated_destination.__dict__
        )

    async def delete_destination(
        self,
        destination_id: int,
    ) -> None:
        """Delete an audit destination.

        Args:
            destination_id (int): The ID of the destination to delete.

        Raises:
            AuditNotFoundError: If the destination with ID does not exist.

        """
        destination = await self._destination_dao.get_destination_by_id(
            destination_id
        )
        await self._destination_dao.delete_destination(destination)
