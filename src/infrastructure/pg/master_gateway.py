"""Master DB Gateway.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from loguru import logger
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from enums import PostgresRWModeType


class PGMasterGateway:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    async def check_master(self) -> bool:
        if self._settings.POSTGRES_RW_MODE == PostgresRWModeType.SINGLE:
            return True

        try:
            self._session.sync_session.set_force_master(True)  # type: ignore
            await self._session.execute(text("SELECT 1"))
        except OperationalError as e:
            logger.error(f"Master DB check failed: {e}")
            return False
        else:
            self._session.sync_session.set_force_master(False)  # type: ignore
            return True
