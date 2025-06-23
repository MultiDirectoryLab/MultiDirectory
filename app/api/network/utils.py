"""Network utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import NetworkPolicy


async def check_policy_count(session: AsyncSession) -> None:
    """Check if policy count euqals 1.

    Raises:
        HTTPException: 422
    """
    count = await session.scalars(
        (
            select(func.count())
            .select_from(NetworkPolicy)
            .filter_by(enabled=True)
        ),
    )

    if count.one() == 1:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "At least one policy should be active",
        )
