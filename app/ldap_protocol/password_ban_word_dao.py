"""Password Ban Word DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import PasswordBanWord


class PasswordBanWordDAO:
    """Password Ban Word DAO."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Password Ban Word DAO with session."""
        self._session = session

    async def create_one(self, word: str) -> None:
        """Create a new banned password word."""
        if len(word) < 3:
            raise ValueError(
                f"Banned word `{word}` must be at least 3 characters long"
            )

        word = word.lower()

        if await self.get_one_by_word(word):
            raise PermissionError(
                f"Word `{word}` already exists in banned list"
            )

        self._session.add(PasswordBanWord(word=word))

    async def get_one_by_word(
        self,
        word: str,
    ) -> PasswordBanWord | None:
        """Get PasswordBanWord if exists.

        :param str word: Banned Password Word.
        :return PasswordBanWord | None: Instance of PasswordBanWord if exists.
        """
        if len(word) < 3:
            raise ValueError(
                f"Banned word `{word}` must be at least 3 characters long"
            )

        word = word.lower()

        result = await self._session.execute(
            select(PasswordBanWord)
            .where(PasswordBanWord.word == word)
        )  # fmt: skip

        return result.scalar_one_or_none()

    async def contain_ban_word(
        self,
        string: str,
    ) -> bool:
        """Try to find banned words into string.

        :param str string: string.
        :return bool: True if banned word found, False otherwise.
        """
        if len(string) < 3:
            raise ValueError(
                f"String `{string}` must be at least 3 characters long"
            )

        string = string.lower()

        result = await self._session.scalar(
            select(PasswordBanWord)
            .where(literal(string).contains(PasswordBanWord.word))
        )  # fmt: skip
        return bool(result)
