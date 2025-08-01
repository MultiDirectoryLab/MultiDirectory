"""Audit policies service module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.exc import IntegrityError

from .dataclasses import AuditDestinationDTO, AuditPolicyDTO
from .destination_dao import AuditDestinationDAO
from .exception import AuditAlreadyExistsError
from .policies_dao import AuditPoliciesDAO


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

    async def get_policies(self) -> list[AuditPolicyDTO]:
        """Get all audit policies."""
        return await self._policy_dao.get_policies()

    async def update_policy(
        self,
        policy_id: int,
        policy_dto: AuditPolicyDTO,
    ) -> None:
        """Update an existing audit policy.

        Args:
            policy_id (int): The ID of the policy to update.
            policy_dto (AuditPolicyDTO): The new policy data.

        Raises:
            AuditNotFoundError: If the policy with the given ID does not exist.
            AuditAlreadyExistsError: If the policy already exists.

        """
        try:
            return await self._policy_dao.update_policy(
                policy_id,
                policy_dto,
            )
        except IntegrityError:
            raise AuditAlreadyExistsError("Audit policy already exists")

    async def get_destinations(self) -> list[AuditDestinationDTO]:
        """Get all audit destinations."""
        return await self._destination_dao.get_destinations()

    async def create_destination(
        self,
        destination_dto: AuditDestinationDTO,
    ) -> None:
        """Create a new audit destination.

        Args:
            destination_dto (AuditDestinationDTO): Destination data to create.

        Raises:
            AuditAlreadyExistsError: If the destination already exists.

        """
        try:
            return await self._destination_dao.create_destination(
                destination_dto,
            )
        except IntegrityError:
            raise AuditAlreadyExistsError("Audit destination already exists")

    async def update_destination(
        self,
        destination_id: int,
        destination_dto: AuditDestinationDTO,
    ) -> None:
        """Update an existing audit destination.

        Args:
            destination_id (int): The ID of the destination to update.
            destination_dto (AuditDestinationDTO): New destination data.

        Raises:
            AuditNotFoundError: If the destination with ID does not exist.
            AuditAlreadyExistsError: If the destination already exists.

        """
        try:
            return await self._destination_dao.update_destination(
                destination_id,
                destination_dto,
            )
        except IntegrityError:
            raise AuditAlreadyExistsError("Audit destination already exists")

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
        await self._destination_dao.delete_destination(destination_id)
