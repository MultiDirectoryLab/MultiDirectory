"""Password Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Iterable, Self

from passlib.exc import UnknownHashError

from ldap_protocol.policies.password.ban_word_repository import (
    PasswordBanWordRepository,
)
from ldap_protocol.policies.password.settings import PasswordValidatorSettings
from password_utils import PasswordUtils

from .error_messages import ErrorMessages
from .settings import PasswordValidatorLanguageType

type _CheckType = Callable[..., Coroutine[Any, Any, bool]]


@dataclass
class _Checker:
    """Checker dataclass."""

    check: _CheckType
    args: list[Any]
    error_message: str


class PasswordPolicyValidator:
    """Builder for password validation rules.

    This class accumulates checks and validates a password against them.
    """

    _checkers: list[_Checker]
    _password_validator_settings: PasswordValidatorSettings
    _password_utils: PasswordUtils

    error_messages: list[str]

    def __init__(
        self,
        password_validator_settings: PasswordValidatorSettings,
        password_utils: PasswordUtils,
    ) -> None:
        """Initialize a new validator instance.

        Sets up internal storage for checkers and default settings.
        """
        self._checkers: list[_Checker] = []
        self._password_validator_settings = password_validator_settings
        self._password_utils = password_utils
        self.error_messages: list[str] = []

    def setup_language(self, language: PasswordValidatorLanguageType) -> None:
        """Set up language for password policy validation."""
        self._password_validator_settings.setup_language(language)

    def __add_checker(
        self,
        check: _CheckType,
        error_message: str,
        args: list,
    ) -> None:
        self._checkers.append(
            _Checker(
                check=check,
                args=args,
                error_message=error_message,
            ),
        )

    async def __run_checker(self, checker: _Checker, password: str) -> None:
        result = await checker.check(
            password,
            self._password_validator_settings,
            *checker.args,
        )
        if result is False:
            self.error_messages.append(checker.error_message)

    async def validate(self, password: str) -> bool:
        """Validate the given password against the configured schema.

        Runs all registered checks and collects error messages.

        :param str password: Password to validate.
        :return: bool.

        :Example:
            .. code-block:: python

                assert not await (
                    PasswordPolicyValidator()
                    .min_length(3)
                    .validate("13")
                )
                assert await (
                    PasswordPolicyValidator().min_length(3).validate("abc")
                )
        """  # fmt: skip
        self.error_messages = []
        for checker in self._checkers:
            await self.__run_checker(checker, password)

        return not bool(self.error_messages)

    def language(self) -> Self:
        """Require password letters to be from the configured language.

        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_language,
            error_message=ErrorMessages.UNAUTHORIZED_LANGUAGE,
            args=[],
        )
        return self

    async def _validate_language(
        self,
        password: str,
        settings: PasswordValidatorSettings,
    ) -> bool:
        """Validate password letters language."""
        matches = re.findall(settings.regexp_not_valid_letters, password)
        return not matches

    def min_length(self, length: int) -> Self:
        """Require minimum password length.

        :param int length: Minimal allowed length.
        :return: PasswordPolicyValidator.

        :Example:
            .. code-block:: python

                assert await (
                    PasswordPolicyValidator()
                    .min_length(8)
                    .validate("testPassword")
                )
                assert not await (
                    PasswordPolicyValidator()
                    .min_length(8)
                    .validate("test")
                )
        """  # fmt: skip
        self.__add_checker(
            check=self._validate_min_length,
            error_message=ErrorMessages.LONGER,
            args=[length],
        )
        return self

    def reuse_prevention(
        self,
        password_history: Iterable[str],
    ) -> Self:
        """Disallow reuse of any password from history.

        :param  Iterable[str] password_history: Iterable of previous
        password hashes.

        :return: PasswordPolicyValidator.
        """
        self.__add_checker(
            check=self._validate_reuse_prevention,
            error_message=ErrorMessages.NOT_IN_HISTORY,
            args=[password_history],
        )
        return self

    def not_otp_like_suffix(self) -> Self:
        """Forbid an OTP-like numeric suffix of configured length.

        :return: PasswordPolicyValidator.

        :Example:
            .. code-block:: python

                assert not await (
                    PasswordPolicyValidator()
                    .not_otp_like_suffix()
                    .validate("test123456")
                )
                assert await (
                    PasswordPolicyValidator()
                    .not_otp_like_suffix()
                    .validate("test12345")
                )
        """  # fmt: skip
        self.__add_checker(
            check=self._validate_not_otp_like_suffix,
            error_message=ErrorMessages.NOT_LIKE_OTP,
            args=[],
        )
        return self

    def min_age(
        self,
        min_age_days: int,
        value: str | None,
    ) -> Self:
        """Require minimal age for the password.

        :param int min_age_days: Minimal age in days
        to allow update.
        :param str | None value: Windows filetime string representing last
        change, or ``None``.
        :return: PasswordPolicyValidator.

        :Note:
            If ``min_age_days`` is ``0`` or ``value`` is ``None``,
            the check passes.
        """
        self.__add_checker(
            check=self._validate_min_age,
            error_message=ErrorMessages.NOT_OLD_ENOUGH,
            args=[min_age_days, value],
        )
        return self

    @staticmethod
    async def _validate_min_length(password: str, _: Any, length: int) -> bool:
        """Validate minimum password length."""
        return len(password) >= length

    async def _validate_reuse_prevention(
        self,
        password: str,
        _: PasswordValidatorSettings,
        password_history: Iterable[str],
    ) -> bool:
        """Check if password is not in the password history."""
        for password_hash in password_history:
            try:
                if self._password_utils.verify_password(
                    password,
                    password_hash,
                ):
                    return False
            except UnknownHashError:
                pass

        return True

    async def _validate_not_otp_like_suffix(
        self,
        password: str,
        settings: PasswordValidatorSettings,
    ) -> bool:
        """Check if password does not end with a specified number of digits."""
        tail = password[-settings.otp_tail_size :]
        res = tail.isdecimal()
        return not res

    async def _validate_min_age(
        self,
        _: str,
        __: PasswordValidatorSettings,
        min_age_days: int,
        value: str | None,
    ) -> bool:
        """Check if password is older than a specified number of days."""
        if min_age_days == 0:
            return True

        if not value:
            return True

        return (
            self._password_utils.count_password_age_days(value) >= min_age_days
        )

    def min_lowercase_letters_count(self, count: int) -> Self:
        """Require minimum count of lowercase letters.

        :param int count: Number of lowercase letters required.

        :return PasswordPolicyValidator: Updated validator object.

        """
        self.__add_checker(
            check=self._validate_min_lowercase_letters_count,
            error_message=ErrorMessages.MORE_LOWERCASE_LETTERS,
            args=[count],
        )
        return self

    async def _validate_min_lowercase_letters_count(
        self,
        password: str,
        settings: PasswordValidatorSettings,
        count: int,
    ) -> bool:
        """Validate minimum lowercase letters count in password."""
        matches = re.findall(settings.regexp_lowercase_letters, password)
        res = len(matches)
        return res >= count

    def min_uppercase_letters_count(self, count: int) -> Self:
        """Require minimum count of uppercase letters.

        :param int count: Number of uppercase letters required.
        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_min_uppercase_letters_count,
            error_message=ErrorMessages.MORE_UPPERCASE_LETTERS,
            args=[count],
        )
        return self

    async def _validate_min_uppercase_letters_count(
        self,
        password: str,
        settings: PasswordValidatorSettings,
        count: int,
    ) -> bool:
        """Validate minimum uppercase letters count in password."""
        matches = re.findall(settings.regexp_uppercase_letters, password)
        res = len(matches)
        return res >= count

    def min_letters_count(self, count: int) -> Self:
        """Require minimum count of any letters.

        :param int count: Number of letters required.
        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_min_letters_count,
            error_message=ErrorMessages.MORE_LETTERS,
            args=[count],
        )
        return self

    async def _validate_min_letters_count(
        self,
        password: str,
        settings: PasswordValidatorSettings,
        count: int,
    ) -> bool:
        """Validate minimum letters count in password."""
        matches = re.findall(settings.regexp_letters, password)
        res = len(matches)
        return res >= count

    def min_digits_count(self, count: int) -> Self:
        """Require minimum count of digits.

        :param int count: Number of digits required.
        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_min_digits_count,
            error_message=ErrorMessages.MORE_DIGITS,
            args=[count],
        )
        return self

    async def _validate_min_digits_count(
        self,
        password: str,
        settings: PasswordValidatorSettings,
        count: int,
    ) -> bool:
        """Validate minimum digits count in password."""
        matches = re.findall(settings.regexp_digits, password)
        res = len(matches)
        return res >= count

    def max_length(self, length: int) -> Self:
        """Require maximum count of characters.

        :param int length: Maximum length allowed.
        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_max_length,
            error_message=ErrorMessages.SHORTER,
            args=[length],
        )
        return self

    async def _validate_max_length(
        self,
        password: str,
        _: PasswordValidatorSettings,
        length: int,
    ) -> bool:
        """Validate maximum password length."""
        return len(password) <= length

    def min_unique_symbols_count(self, count: int) -> Self:
        """Require minimum count of unique symbols.

        :param int count: Number of unique symbols required.
        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_min_unique_symbols_count,
            error_message=ErrorMessages.MORE_UNIQUE_SYMBOLS,
            args=[count],
        )
        return self

    async def _validate_min_unique_symbols_count(
        self,
        password: str,
        _: PasswordValidatorSettings,
        count: int,
    ) -> bool:
        """Validate minimum unique symbols count in password."""
        return len(set(password)) >= count

    def max_sequential_alphabet_symbols_count(self, count: int) -> Self:
        """Require maximum count of sequential alphabet symbols in row.

        :param int count: Number of sequential alphabet symbols in a row.
        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_max_sequential_alphabet_symbols_count,
            error_message=ErrorMessages.FEWER_ALPHABET_LETTERS,
            args=[count],
        )
        return self

    async def _validate_max_sequential_alphabet_symbols_count(
        self,
        password: str,
        settings: PasswordValidatorSettings,
        count: int,
    ) -> bool:
        """Validate maximum sequential alphabet symbols count in password.

        Slice lower password and slice alphabet sequence.
        Then check if there is an intersection between two sets of slices.
        If there is an intersection, return False.
        If there is no intersection, return True.
        """
        pwd = password.lower()
        subpwd = set(pwd[i : i + count] for i in range(len(pwd) - count + 1))
        subseq = set(
            settings.alphabet_sequence[i : i + count]
            for i in range(len(settings.alphabet_sequence) - count + 1)
        )

        res = subpwd & subseq
        return not res

    def max_sequential_keyboard_symbols_count(self, count: int) -> Self:
        """Require maximum count of sequential keyboard symbols in row.

        :param int count: Number of sequential keyboard symbols in a row.
        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_max_sequential_keyboard_symbols_count,
            error_message=ErrorMessages.FEWER_KEYBOARD_CHARACTERS,
            args=[count],
        )
        return self

    async def _validate_max_sequential_keyboard_symbols_count(
        self,
        password: str,
        settings: PasswordValidatorSettings,
        count: int,
    ) -> bool:
        """Validate maximum sequential keyboard symbols count in password.

        Slice lower password and slice keyboard sequences.
        Then check if there is an intersection between two sets of slices.
        If there is an intersection, return False.
        If there is no intersection, return True.
        """
        pwd = password.lower()
        subpwd = set(pwd[i : i + count] for i in range(len(pwd) - count + 1))

        for seq in settings.keyboard_sequences:
            subseq = set(
                seq[i : i + count] for i in range(len(seq) - count + 1)
            )
            if subpwd & subseq:
                return False

        return True

    def max_repeating_symbols_in_row_count(self, count: int) -> Self:
        """Require maximum count of repeating symbols in row.

        :param int count: Number of repeating symbols in a row.
        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_max_repeating_symbols_in_row_count,
            error_message=ErrorMessages.FEWER_REPEATING_CHARACTERS,
            args=[count],
        )
        return self

    async def _validate_max_repeating_symbols_in_row_count(
        self,
        password: str,
        _: Any,
        count: int,
    ) -> bool:
        """Validate maximum repeating symbols in row count in password."""
        matches = re.findall(rf"(.)\1{{{count}}}+", password)
        return not matches

    def min_special_symbols_count(self, count: int) -> Self:
        """Count minimum of special symbols (neither letters nor numbers)."""
        self.__add_checker(
            check=self._validate_min_special_symbols_count,
            error_message=ErrorMessages.MORE_SPECIAL_SYMBOLS,
            args=[count],
        )
        return self

    async def _validate_min_special_symbols_count(
        self,
        password: str,
        settings: PasswordValidatorSettings,
        count: int,
    ) -> bool:
        """Validate minimum special symbols count in password."""
        matches = re.findall(settings.regexp_special_symbols, password)
        res = len(matches)
        return res >= count

    def not_equal_any_ban_word(
        self,
        password_ban_word_repository: PasswordBanWordRepository,
    ) -> Self:
        """Require the password to not be in a common password list."""
        self.__add_checker(
            check=self._validate_not_equal_any_ban_word,
            error_message=ErrorMessages.NOT_EQUAL_BAN_WORD,
            args=[password_ban_word_repository],
        )
        return self

    async def _validate_not_equal_any_ban_word(
        self,
        password: str,
        _: PasswordValidatorSettings,
        password_ban_word_repository: PasswordBanWordRepository,
    ) -> bool:
        """Check if password is not equal to any banned word."""
        res = await password_ban_word_repository.get_by_word(password)
        return not res

    def not_contain_any_ban_word(
        self,
        password_ban_word_repository: PasswordBanWordRepository,
    ) -> Self:
        """Require the password to not contain any common password words.

        :param PasswordBanWordRepository password_ban_word_repository:
            repository to interact with PasswordBanWord
        :return PasswordPolicyValidator: Updated validator object.
        """
        self.__add_checker(
            check=self._validate_not_contain_any_ban_word,
            error_message=ErrorMessages.NOT_CONTAIN_BAN_WORD,
            args=[
                password_ban_word_repository,
            ],
        )
        return self

    async def _validate_not_contain_any_ban_word(
        self,
        password: str,
        _: PasswordValidatorSettings,
        password_ban_word_repository: PasswordBanWordRepository,
    ) -> bool:
        """Check if password not contain any banned words."""
        return not (
            await password_ban_word_repository.is_ban_word_contains_in_pattern(
                password,
            )
        )
