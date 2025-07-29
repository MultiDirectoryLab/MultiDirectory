"""Audit policies dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditPolicy, AuditPolicyTrigger


class AuditPoliciesDAO:
    """Audit DAO for managing audit policies."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Audit DAO with a database session."""
        self._session = session

    async def create_policy(
        self,
        policy: AuditPolicy,
        triggers: list[AuditPolicyTrigger],
    ) -> None:
        """Create a new audit policy."""
        for trigger in triggers:
            trigger.audit_policy = policy

        self._session.add_all([policy, *triggers])
        await self._session.flush()
