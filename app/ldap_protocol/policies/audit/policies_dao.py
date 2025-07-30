"""Audit policies dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict

from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditPolicy, AuditPolicyTrigger

from .dataclasses import AuditPolicyDTO, AuditPolicyTriggerDTO


class AuditPoliciesDAO:
    """Audit DAO for managing audit policies."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Audit DAO with a database session."""
        self._session = session

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
