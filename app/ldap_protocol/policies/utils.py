"""Utils for policies.

Utils for policies.
Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import time
from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy.ext.asyncio import AsyncSession

from models import Attribute, Directory


async def add_lock_and_expire_attributes(
    session: AsyncSession,
    directory: Directory,
    tz: ZoneInfo,
) -> None:
    """Add `nsAccountLock` and `shadowExpire` attributes to the directory."""
    now_with_tz = datetime.now(tz=tz)
    absolute_date = int(time.mktime(now_with_tz.timetuple()) / 86400)
    session.add_all(
        [
            Attribute(
                name="nsAccountLock",
                value="true",
                directory=directory,
            ),
            Attribute(
                name="shadowExpire",
                value=str(absolute_date),
                directory=directory,
            ),
        ]
    )
    await session.flush()
