"""Audit policies dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditPolicy, AuditPolicyTrigger

from .dataclasses import (
    AuditPolicyDTO,
    AuditPolicySetupDTO,
    AuditPolicyTriggerDTO,
)
from .exception import AuditNotFoundError


class AuditPoliciesDAO:
    """Audit DAO for managing audit policies."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Audit DAO with a database session."""
        self._session = session

    async def get_policies(self) -> list[AuditPolicyDTO]:
        """Get all audit policies."""
        return [
            AuditPolicyDTO(
                id=policy.id,
                name=policy.name,
                is_enabled=policy.is_enabled,
                severity=policy.severity,
            )
            for policy in (
                await self._session.scalars(select(AuditPolicy))
            ).all()
        ]

    async def get_policy_by_id(self, policy_id: int) -> AuditPolicy:
        """Get an audit policy by its ID.

        Args:
            policy_id (int): The ID of the audit policy to retrieve.

        Raises:
            AuditNotFoundError: If the policy with the given ID does not exist.

        """
        policy = await self._session.get(AuditPolicy, policy_id)
        if not policy:
            raise AuditNotFoundError(f"Policy with id {policy_id} not found.")
        return policy

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
            IntegrityError: If the policy already exists with the same name.

        """
        existing_policy = await self.get_policy_by_id(policy_id)

        existing_policy.id = policy_dto.id
        existing_policy.name = policy_dto.name
        existing_policy.is_enabled = policy_dto.is_enabled

        await self._session.flush()

    async def create_policy(
        self,
        policy_dto: AuditPolicySetupDTO,
        triggers_dto: list[AuditPolicyTriggerDTO],
    ) -> None:
        """Create a new audit policy."""
        policy = AuditPolicy(**policy_dto.as_dict())
        triggers = list()

        for trigger_dto in triggers_dto:
            trigger = AuditPolicyTrigger(**asdict(trigger_dto))
            trigger.audit_policy = policy
            triggers.append(trigger)

        self._session.add_all([policy, *triggers])
        await self._session.flush()
