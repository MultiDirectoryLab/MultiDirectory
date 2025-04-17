"""Check if events need to be processed.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from redis_client import RedisClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditPolicy


async def check_events_to_process(
    session: AsyncSession, redis_client: RedisClient
) -> None:
    """Check if events need to be processed and set if need."""
    enabled_audit_policies = (await session.scalars(
        select(AuditPolicy)
        .where(AuditPolicy.is_enabled.is_(True))
    )).all()  # fmt: skip

    if enabled_audit_policies:
        await redis_client.enable_proc_events()
        return

    await redis_client.disable_proc_events()
