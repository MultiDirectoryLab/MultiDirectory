"""Utils with master database check.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from enums import PostgresRWModeType


@inject
async def require_master_db(
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
) -> None:
    if settings.POSTGRES_RW_MODE == PostgresRWModeType.SINGLE:
        return

    try:
        session.sync_session.set_force_master(True)  # type: ignore
        await session.execute(text("SELECT 1"))
    except OperationalError as e:
        logger.error(f"Master DB check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Master DB is not available",
        )
    else:
        session.sync_session.set_force_master(False)  # type: ignore
