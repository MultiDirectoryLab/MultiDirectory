"""Audit policies dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditPolicy, AuditPolicyTrigger

from .dataclasses import AuditPolicyDTO, AuditPolicyTriggerDTO
from .exception import AuditNotFoundError


class AuditPoliciesDAO:
    """Audit DAO for managing audit policies."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Audit DAO with a database session."""
        self._session = session

    async def get_policies(self) -> list[AuditPolicy]:
        """Get all audit policies."""
        return list((await self._session.scalars(select(AuditPolicy))).all())

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
        old_policy: int,
        policy_id: int,
        name: str,
        is_enabled: bool,
    ) -> None:
        """Update an existing audit policy.

        Args:
            old_policy (int): The existing policy ID.
            policy_id (int): The ID of the policy to update.
            name (str): The new name for the policy.
            is_enabled (bool): The new enabled status for the policy.

        Raises:
            IntegrityError: If the policy already exists with the same name.

        """
        existing_policy = await self.get_policy_by_id(old_policy)
        existing_policy.id = policy_id
        existing_policy.name = name
        existing_policy.is_enabled = is_enabled
        await self._session.flush()

    async def create_policy(
        self,
        policy_dto: AuditPolicyDTO,
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
