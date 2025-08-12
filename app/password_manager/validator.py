"""Password Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Self

from sqlalchemy.ext.asyncio import AsyncSession

from . import checks
from .error_messages import ErrorMessages
from .settings import _PasswordValidatorSettings

type _CheckType = Callable[..., Coroutine[Any, Any, bool]]


@dataclass
class _Checker:
    """Checker dataclass."""

    check: _CheckType
    args: list[Any]
    error_message: str


class PasswordValidator:
    """Class to generate schema of password definitions.

    pwd_val = PasswordValidator("Latin", session)

    Example:
        >>> pwd_val.min_length(6).min_digits_count(2).min_letters_count(4)
        <...PasswordValidator object at ...>
        >>> pwd_val.validate("t3stPa$$w0rD132")
        True

    Returns:
        PasswordValidator: Schema object of validation.

    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        """Create new instance of the PasswordValidator class."""
        self.__checkers: list[_Checker] = []
        self.__settings: _PasswordValidatorSettings = (
            _PasswordValidatorSettings(
                session,
            )
        )
        self.error_messages: list[str] = []

    def __add_checker(
        self,
        check: _CheckType,
        error_message: str,
        args: list,
    ) -> None:
        self.__checkers.append(
            _Checker(
                check=check,
                args=args,
                error_message=error_message,
            ),
        )

    async def __run_checker(self, checker: _Checker, password: str) -> None:
        result = await checker.check(password, self.__settings, *checker.args)
        if result is False:
            self.error_messages.append(checker.error_message)

    async def validate(self, password: str) -> bool:
        """Validate `password` against the schema and returns the result.

        Example:
            >>> pwd_val.min_letters_count(2).validate("123")
            False
            >>> pwd_val.min_letters_count(2).validate("abc")
            True

        Args:
            password (str): Password to validate against the schema.

        Returns:
            boolean: Result of the validation.

        """
        self.error_messages = []
        for checker in self.__checkers:
            await self.__run_checker(checker, password)

        return not bool(self.error_messages)

    def min_length(self, length: int) -> Self:
        """Require minimum count of characters.

        Example:
            >>> pwd_val.min(8).validate("testPassword")
            True
            >>> pwd_val.min(8).validate("test")
            False

        Args:
            length (int): Minimum length allowed.

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.min_length,
            error_message=ErrorMessages.LONGER,
            args=[length],
        )
        return self

    def reuse_prevention(
        self,
        password_history: list[str],
    ) -> Self:
        """Mandates the presence of password history.

        Args:
            password_history (list[str]): List of previous password hashes.

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.reuse_prevention,
            error_message=ErrorMessages.NOT_IN_HISTORY,
            args=[password_history],
        )
        return self

    def not_otp_like_suffix(self) -> Self:
        """OTP-like suffix check.

        Example:
            >>> pwd_val.not_otp_like_suffix().validate("test123456")
            False
            >>> pwd_val.not_otp_like_suffix().validate("test12345")
            True

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.not_otp_like_suffix,
            error_message=ErrorMessages.NOT_LIKE_OTP,
            args=[],
        )
        return self

    def not_equal_any_ban_word(self) -> Self:
        """Require the password to not be in a common password list.

        Example:
            >>> pwd_val.not_equal_any_ban_word().validate("MyPassword")
            False
            >>> pwd_val.not_equal_any_ban_word().validate("un1q.Pa$$w0rd")
            True

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.not_equal_any_ban_word,
            error_message=ErrorMessages.NOT_EQUAL_BAN_WORD,
            args=[],
        )
        return self

    def not_contain_any_ban_word(self) -> Self:
        """Require the password to not contain any common password words.

        Example:
            >>> pwd_val.not_contain_any_ban_word().validate("Alex")
            False
            >>> pwd_val.not_contain_any_ban_word().validate("un1q.Pa$$w0rd")
            True

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.not_contain_any_ban_word,
            error_message=ErrorMessages.NOT_CONTAIN_BAN_WORD,
            args=[],
        )
        return self

    def min_age(
        self,
        min_age_days: int,
        value: str | None,
    ) -> Self:
        """Require minimum age of the password.

        Example:
            >>> # value is windows filetime, equal 7 days
            >>> pwd_val.min_age(6, value).validate()
            True
            >>> pwd_val.min_age(8, value).validate()
            False

        Args:
            min_age_days (int): Minimum age in days.
            value (str | None): Value to check against.

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.min_age,
            error_message=ErrorMessages.NOT_OLD_ENOUGH,
            args=[min_age_days, value],
        )
        return self
