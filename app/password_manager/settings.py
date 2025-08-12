"""Password Validator Settings.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.data_access_objects import PasswordBanWordDAO

type PasswordValidatorLanguageType = Literal["Cyrillic", "Latin"]

_REGEXP_DIGITS: str = r"\d"


class _PasswordValidatorSettings:
    """Password Validator Settings."""

    password_ban_word_dao: PasswordBanWordDAO

    otp_tail_size: Literal[6] = 6
    alphabet_sequence: str
    keyboard_sequences: list[str]
    regexp_letters: str
    regexp_digits: str = _REGEXP_DIGITS
    regexp_not_valid_letters: str
    regexp_special_symbols: str
    regexp_uppercase_letters: str
    regexp_lowercase_letters: str

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        """Init Password Validator Settings."""
        self.password_ban_word_dao = PasswordBanWordDAO(session)
