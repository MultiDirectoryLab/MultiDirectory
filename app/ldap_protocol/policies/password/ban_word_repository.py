"""Password Ban Word DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable

from sqlalchemy import delete, literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_service import AbstractService
from entities import PasswordBanWord
from ldap_protocol.policies.password.exceptions import (
    PasswordBanWordFileHasDuplicatesError,
)
from repo.pg.tables import queryable_attr as qa


class PasswordBanWordRepository(AbstractService):
    """Password Ban Word Repository."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Password Ban Word DAO with session."""
        self.__session = session

    async def get_by_word(self, word: str) -> str | None:
        """Get Password Ban Word by word.

        :param str word: word.
        :return PasswordBanWord | None: Password Ban Word or None if not found.
        """
        ban_word = await self.__session.scalar(
            select(qa(PasswordBanWord.word))
            .where(qa(PasswordBanWord.word) == word.lower()),
        )  # fmt: skip

        return ban_word if ban_word else None

    async def is_ban_word_contains_in_pattern(self, pattern: str) -> bool:
        """Check if the pattern contains any banned words.

        :param str pattern: pattern.
        :return bool: True if banned word found, False otherwise.
        """
        result = await self.__session.scalar(
            select(qa(PasswordBanWord.word))
            .where(literal(pattern.lower()).contains(PasswordBanWord.word)),
        )  # fmt: skip
        return bool(result)

    async def get_all(self) -> Iterable[str]:
        """Get all Password Ban Words.

        :return list[PasswordBanWord]: list of Password Ban Words.
        """
        return await self.__session.scalars(select(qa(PasswordBanWord.word)))

    async def delete_all(self) -> None:
        """Delete all ban words."""
        await self.__session.execute(delete(PasswordBanWord))

    async def create(self, ban_word: str) -> None:
        """Create password ban word."""
        self.__session.add(PasswordBanWord(word=ban_word.lower()))

    async def replace(self, ban_words: Iterable[str]) -> None:
        """Replace Password Ban Words."""
        await self.delete_all()

        for ban_word in ban_words:
            await self.create(ban_word)

        try:
            await self.__session.commit()
        except IntegrityError:
            await self.__session.rollback()
            raise PasswordBanWordFileHasDuplicatesError(
                "Ban words is duplicated",
            )
