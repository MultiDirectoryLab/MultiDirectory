"""Password Ban Word DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable, Literal

from pydantic import BaseModel
from sqlalchemy import delete, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.pagination import BasePaginationSchema
from models import PasswordBanWord


class PasswordBanWordSchema(BaseModel):
    """Password Ban Word Schema."""

    word: str

    @classmethod
    def from_db(
        cls,
        password_ban_word: PasswordBanWord,
    ) -> "PasswordBanWordSchema":
        """Create an instance of Password Ban Word Schema from SQLA object."""
        return cls(word=password_ban_word.word)


class PasswordBanWordPaginationSchema(
    BasePaginationSchema[PasswordBanWordSchema],
):
    """Common Password Schema with pagination result."""

    items: list[PasswordBanWordSchema]


class PasswordBanWordDAO:
    """Password Ban Word DAO."""

    __session: AsyncSession

    # Min string length to be included in GIN index trigram search (pg_trgm)
    __MIN_LENGTH_FOR_TRGM: Literal[3] = 3

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Password Ban Word DAO with session."""
        self.__session = session

    async def get_one_by_word(self, word: str) -> PasswordBanWord | None:
        """Get Password Ban Word by word.

        :param str word: word.
        :return PasswordBanWord | None: Password Ban Word or None if not found.
        """
        return await self.__session.scalar(
            select(PasswordBanWord)
            .where(PasswordBanWord.word == word.lower()),
        )  # fmt: skip

    async def get_all(self) -> list[PasswordBanWord]:
        """Get all Password Ban Words.

        :return list[PasswordBanWord]: list of Password Ban Words.
        """
        res = await self.__session.scalars(select(PasswordBanWord))
        return list(res)

    async def replace_all(self, ban_words: Iterable[str]) -> None:
        """Replace Password Ban Words."""
        await self.__session.execute(delete(PasswordBanWord))

        ban_words = [
            ban_word.lower()
            for ban_word in ban_words
            if len(ban_word) >= self.__MIN_LENGTH_FOR_TRGM
        ]

        for ban_word in ban_words:
            self.__session.add(PasswordBanWord(word=ban_word))

    async def contain_any_ban_word(self, string: str) -> bool:
        """Try to find banned words into string.

        :param str string: string.
        :return bool: True if banned word found, False otherwise.
        """
        if len(string) < self.__MIN_LENGTH_FOR_TRGM:
            raise ValueError(
                f"String `{string}` must be "
                f"at least {self.__MIN_LENGTH_FOR_TRGM} characters long",
            )

        string = string.lower()

        result = await self.__session.scalar(
            select(PasswordBanWord)
            .where(literal(string).contains(PasswordBanWord.word)),
        )  # fmt: skip
        return bool(result)
