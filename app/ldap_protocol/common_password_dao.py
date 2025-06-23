"""Common Password DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import CommonPassword


class CommonPasswordDAO:
    """Common Password DAO."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Common Password DAO with session."""
        self._session = session

    async def create_one(self, password: str) -> None:
        """Create a new common password."""
        password = password.lower()

        if await self.get_one_by_password(password):
            raise PermissionError(
                f"Password `{password}` already exists in common list"
            )

        self._session.add(CommonPassword(password=password))

    async def get_one_by_password(
        self,
        password: str,
    ) -> CommonPassword | None:
        """Get single Common Password if exists.

        :param str password: Common Password.
        :return CommonPassword | None: Instance of Common Password if exists.
        """
        password = password.lower()

        result = await self._session.execute(
            select(CommonPassword)
            .where(CommonPassword.password == password)
        )  # fmt: skip

        return result.scalar_one_or_none()
