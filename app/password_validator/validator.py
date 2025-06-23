"""Password Validator.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Literal, Self

from sqlalchemy.ext.asyncio import AsyncSession

from . import checks

CheckType = Callable[..., Coroutine[Any, Any, bool]]

_OTP_TAIL_SIZE: Literal[6] = 6


@dataclass
class Checker:
    """Checker dataclass."""

    check: CheckType
    args: list[Any]
    error_message: str


class PasswordValidator:
    """Class to generate schema of password definitions.

    Example:
        >>> schema = PasswordValidator()
        >>> schema.min_length(6).min_digits_count(2).min_letters_count(4)
        <...PasswordValidator object at ...>
        >>> schema.validate("t3stPa$$w0rD132")
        True

    Returns:
        PasswordValidator: Schema object of validation.

    """

    def __init__(self) -> None:
        """Create new instance of the PasswordValidator class."""
        self.checkers: list[Checker] = []
        self.error_messages: list[str] = []

    def __add_checker(
        self,
        check: CheckType,
        error_message: str,
        args: None | list = None,
    ) -> None:
        self.checkers.append(
            Checker(
                check=check,
                args=args or [],
                error_message=error_message,
            )
        )

    async def __run_checker(self, checker: Checker, password: str) -> None:
        result = await checker.check(password, *checker.args)
        if result is False:
            self.error_messages.append(checker.error_message)

    async def validate(self, password: str) -> bool:
        """Validate `password` against the schema and returns the result.

        Example:
            >>> PasswordValidator().min_letters_count(2).validate("123")
            False
            >>> PasswordValidator().min_letters_count(2).validate("abc")
            True

        Args:
            password (str): Password to validate against the schema.

        Returns:
            boolean: Result of the validation.

        """
        self.error_messages = []
        for checker in self.checkers:
            await self.__run_checker(checker, password)

        return not bool(self.error_messages)

    def min_lowercase_letters_count(self, count: int) -> Self:
        """Require minimum count of lowercase letters.

        Example:
            >>> PasswordValidator().min_lowercase_letters_count(2).validate("Test")
            True
            >>> PasswordValidator().min_lowercase_letters_count(2).validate("TEST")
            False

        Args:
            count (int): Number of lowercase letters required.

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.min_lowercase_letters_count,
            error_message=f"Password must contain {count} or more lowercase letters",  # noqa: E501
            args=[count],
        )
        return self

    def min_uppercase_letters_count(self, count: int) -> Self:
        """Require minimum count of uppercase letters.

        Example:
            >>> PasswordValidator().min_uppercase_letters_count(2).validate("TeSt")
            True
            >>> PasswordValidator().min_uppercase_letters_count(2).validate("teSt")
            False

        Args:
            count (int): Number of uppercase letters required.

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.min_uppercase_letters_count,
            error_message=f"Password must contain {count} or more uppercase letters",  # noqa: E501
            args=[count],
        )
        return self

    def min_letters_count(self, count: int) -> Self:
        """Require minimum count of any letters.

        Example:
            >>> PasswordValidator().min_letters_count(2).validate("tES12345")
            True
            >>> PasswordValidator().min_letters_count(2).validate("t12345")
            False

        Args:
            count (int): Number of letters required.

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.min_letters_count,
            error_message=f"Password must contain {count} or more letters",
            args=[count],
        )
        return self

    def min_digits_count(self, count: int) -> Self:
        """Require minimum count of digits.

        Example:
            >>> PasswordValidator().min_digits_count(3).validate("test123")
            True
            >>> PasswordValidator().min_digits_count(3).validate("test12")
            False

        Args:
            count (int): Number of digits required.

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.min_digits_count,
            error_message=f"Password must contain {count} or more digits",
            args=[count],
        )
        return self

    def min_length(self, length: int) -> Self:
        """Require minimum count of characters.

        Example:
            >>> PasswordValidator().min(8).validate("testPassword")
            True
            >>> PasswordValidator().min(8).validate("test")
            False

        Args:
            length (int): Minimum length allowed.

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.min_length,
            error_message="Password minimum length violation",
            args=[length],
        )
        return self

    def max_length(self, length: int) -> Self:
        """Require maximum count of characters.

        Example:
            >>> PasswordValidator().max(8).validate("testPassword")
            False
            >>> PasswordValidator().max(8).validate("test")
            True

        Args:
            length (int): Maximum length allowed.

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.max_length,
            error_message="Password maximum length violation",
            args=[length],
        )
        return self

    def min_unique_symbols_count(self, count: int) -> Self:
        """Require minimum count of unique symbols.

        Example:
            >>> PasswordValidator().min_unique_symbols_count(3).validate("aaabc")
            True
            >>> PasswordValidator().min_unique_symbols_count(3).validate("aaab")
            False

        Args:
            count (int): Number of unique symbols required.

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.min_unique_symbols_count,
            error_message=f"Password must contain {count} or more unique symbols",  # noqa: E501
            args=[count],
        )
        return self

    def max_sequential_alphabet_symbols_count(self, count: int) -> Self:
        """Require maximum count of sequential alphabet symbols in row.

        Example:
            >>> PasswordValidator().max_sequential_alphabet_symbols_count(3).validate("abcde")
            True
            >>> PasswordValidator().max_sequential_alphabet_symbols_count(3).validate("abc")
            False

        Args:
            count (int): Number of sequential alphabet symbols in a row.

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.max_sequential_alphabet_symbols_count,
            error_message=f"Password must not contain {count} or more sequential alphabet symbols",  # noqa: E501
            args=[count],
        )
        return self

    def max_sequential_keyboard_symbols_count(self, count: int) -> Self:
        """Require maximum count of sequential keyboard symbols in row.

        Example:
            >>> PasswordValidator().max_sequential_keyboard_symbols_count(4).validate("qwerty")
            True
            >>> PasswordValidator().max_sequential_keyboard_symbols_count(4).validate("qwe")
            False

        Args:
            count (int): Number of sequential keyboard symbols in a row.

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.max_sequential_keyboard_symbols_count,
            error_message=f"Password must not contain {count} or more sequential keyboard symbols",  # noqa: E501
            args=[count],
        )
        return self

    def max_repeating_symbols_in_row_count(self, count: int) -> Self:
        """Require maximum count of repeating symbols in row.

        Example:
            >>> PasswordValidator().max_repeating_symbols_in_row_count(3).validate("aaabbb")
            True
            >>> PasswordValidator().max_repeating_symbols_in_row_count(3).validate("aabbccdd")
            False

        Args:
            count (int): Number of repeating symbols in a row.

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.max_repeating_symbols_in_row_count,
            error_message=f"Password must not contain {count} or more repeating symbols in a row",  # noqa: E501
            args=[count],
        )
        return self

    def min_special_symbols_count(self, count: int) -> Self:
        """Require minimum count of special symbols (not letters and not numbers).

        Example:
            >>> PasswordValidator().min_special_symbols_count(3).validate("@bc!_")
            True
            >>> PasswordValidator().min_special_symbols_count(3).validate("@bc!")
            False

        Args:
            count (int): Number of special symbols.

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.min_special_symbols_count,
            error_message=f"Password must contain {count} or more special symbols",  # noqa: E501
            args=[count],
        )
        return self

    def reuse_prevention(
        self,
        password_history: list[str],
        history_slice_size: int,
    ) -> Self:
        """Mandates the presence of password history.

        Args:
            password_history (list[str]): List of previous passwords.
            history_slice_size (int): Number of passwords to check against.

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.reuse_prevention,
            error_message="Password must not be in history",
            args=[password_history, history_slice_size],
        )
        return self

    def not_otp_like_suffix(self) -> Self:
        """OTP-like suffix check.

        Example:
            >>> PasswordValidator().not_otp_like_suffix().validate("test123456")
            False
            >>> PasswordValidator().not_otp_like_suffix().validate("test12345")
            True

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.not_otp_like_suffix,
            error_message=f"Password must not end with {_OTP_TAIL_SIZE} digits",  # noqa: E501
            args=[_OTP_TAIL_SIZE],
        )
        return self

    def not_contains_in_common_list(self, session: AsyncSession) -> Self:
        """Require the password to not be in a common password list.

        Example:
            >>> PasswordValidator().not_contains_in_common_list().validate("123456")
            False
            >>> PasswordValidator().not_contains_in_common_list().validate("un1q.Pa$$w0rd")
            True

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.not_contains_in_common_list,
            error_message="Password must not be a common password",
            args=[session],
        )
        return self

    def not_contain_ban_word(self, session: AsyncSession) -> Self:
        """Require the password to not be in a common password list.

        Example:
            >>> PasswordValidator().not_contain_ban_word().validate("Alex")
            False
            >>> PasswordValidator().not_contain_ban_word().validate("un1q.Pa$$w0rd")
            True

        Returns:
            PasswordValidator: Updated schema object.

        """  # noqa: E501
        self.__add_checker(
            check=checks.not_contain_ban_word,
            error_message="Password must not contain prohibited word",
            args=[session],
        )
        return self

    def min_age(
        self,
        min_age_days: int,
        value: str | None,
    ) -> Self:
        """Require minimum age of the password.

        Example:
            >>> # val is windows filetime, equal 7 days
            >>> PasswordValidator().min_age(6, val).validate()
            True
            >>> PasswordValidator().min_age(8, val).validate()
            False

        Args:
            min_age_days (int): Minimum age in days.
            value (str | None): Value to check against.

        Returns:
            PasswordValidator: Updated schema object.

        """
        self.__add_checker(
            check=checks.min_age,
            error_message="Minimum password age violation",
            args=[min_age_days, value],
        )
        return self
