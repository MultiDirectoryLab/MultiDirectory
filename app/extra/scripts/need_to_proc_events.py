"""Check if events need to be processed.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.policies.audit_policy import RedisAuditDAO
from models import AuditDestination, AuditPolicy


async def check_events_to_process(
    session: AsyncSession, redis_client: RedisAuditDAO
) -> None:
    """Check if events need to be processed and set if need."""
    enabled_audit_policies = (await session.scalars(
        select(AuditPolicy)
        .where(AuditPolicy.is_enabled.is_(True))
    )).all()  # fmt: skip

    enabled_audit_destination = (await session.scalars(
        select(AuditDestination)
        .where(AuditDestination.is_enabled.is_(True))
    )).all()  # fmt: skip

    if enabled_audit_policies and enabled_audit_destination:
        await redis_client.enable_event_processing()
        return

    await redis_client.disable_event_processing()
