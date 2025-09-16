"""Audit policies dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict

from adaptix.conversion import get_converter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_dao import AbstractDAO
from models import AuditPolicy, AuditPolicyTrigger

from .dataclasses import AuditPolicyDTO, AuditPolicySetupDTO
from .exception import AuditNotFoundError

_convert = get_converter(AuditPolicy, AuditPolicyDTO)


class AuditPoliciesDAO(AbstractDAO[AuditPolicyDTO, int]):
    """Audit DAO for managing audit policies."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Audit DAO with a database session."""
        self._session = session

    async def get_all(self) -> list[AuditPolicyDTO]:
        """Get all audit policies."""
        return [
            AuditPolicyDTO(
                id=policy.id,
                name=policy.name,
                is_enabled=policy.is_enabled,
                severity=policy.severity,
            )
            for policy in await self._session.scalars(select(AuditPolicy))
        ]

    async def _get_raw(self, _id: int) -> AuditPolicy:
        """Get an audit policy by its ID.

        Args:
            policy_id (int): The ID of the audit policy to retrieve.

        Raises:
            AuditNotFoundError: If the policy with the given ID does not exist.

        """
        policy = await self._session.get(AuditPolicy, _id)
        if not policy:
            raise AuditNotFoundError(f"Policy with id {_id} not found.")
        return policy

    async def get(self, _id: int) -> AuditPolicyDTO:
        """Get an audit policy by its ID.

        Args:
            policy_id (int): The ID of the audit policy to retrieve.

        Raises:
            AuditNotFoundError: If the policy with the given ID does not exist.

        """
        return _convert(await self._get_raw(_id))

    async def update(self, _id: int, dto: AuditPolicyDTO) -> None:
        """Update an existing audit policy.

        Args:
            _id (int): The ID of the policy to update.
            dto (AuditPolicyDTO): The new policy data.

        Raises:
            IntegrityError: If the policy already exists with the same name.

        """
        existing_policy = await self._get_raw(_id)

        existing_policy.name = dto.name
        existing_policy.is_enabled = dto.is_enabled

        await self._session.flush()

    async def delete(self, _id: int) -> None:
        """Delete an existing audit policy.

        Args:
            _id (int): The ID of the policy to delete.

        Raises:
            AuditNotFoundError: If the policy with the given ID does not exist.

        """
        policy = await self.get(_id)
        await self._session.delete(policy)
        await self._session.flush()

    async def create(
        self,
        dto: AuditPolicySetupDTO,  # type: ignore
    ) -> None:
        """Create a new audit policy."""
        policy = AuditPolicy(**dto.as_dict())
        self._session.add(policy)

        triggers = list()

        for trigger_dto in dto.triggers:
            trigger = AuditPolicyTrigger(**asdict(trigger_dto))
            trigger.audit_policy = policy
            triggers.append(trigger)

        self._session.add_all([policy, *triggers])
        await self._session.flush()
