"""Password Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Iterable, Self

from passlib.exc import UnknownHashError

from config import Settings
from ldap_protocol.policies.password.settings import PasswordValidatorSettings
from password_manager import PasswordValidator

from .error_messages import ErrorMessages

type _CheckType = Callable[..., Coroutine[Any, Any, bool]]

with open("extra/common_pwds.txt") as f:
    _COMMON_PASSWORDS = set(f.read().split("\n"))


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

    def __init__(
        self,
        password_validator_settings: PasswordValidatorSettings,
        password_validator: PasswordValidator,
    ) -> None:
        """Initialize a new validator instance.

        Sets up internal storage for checkers and default settings.
        """
        self._checkers: list[_Checker] = []
        self._password_validator_settings = password_validator_settings
        self._password_validator = password_validator
        self.error_messages: list[str] = []

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
            check=self.validate_min_length,
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
            check=self.validate_reuse_prevention,
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
            check=self.validate_not_otp_like_suffix,
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
            check=self.validate_min_age,
            error_message=ErrorMessages.NOT_OLD_ENOUGH,
            args=[min_age_days, value],
        )
        return self

    def min_complexity(self) -> Self:
        """Require minimum password complexity.

        :return: PasswordPolicyValidator.
        """
        self.__add_checker(
            check=self.validate_min_complexity,
            error_message=ErrorMessages.NOT_COMPLEX_ENOUGH,
            args=[],
        )
        return self

    @staticmethod
    async def validate_min_complexity(password: str, _: Any) -> bool:
        """Validate minimum password complexity.

        :param str password: Password to validate.
        :return: bool
        """
        regex = (
            re.search("[A-ZА-Я]", password) is not None,
            re.search("[a-zа-я]", password) is not None,
            re.search("[0-9]", password) is not None,
            password.lower() not in _COMMON_PASSWORDS,
        )
        return all(regex)

    @staticmethod
    async def validate_min_length(password: str, _: Any, length: int) -> bool:
        """Validate minimum password length."""
        return len(password) >= length

    async def validate_reuse_prevention(
        self,
        password: str,
        _: Settings,
        password_history: Iterable[str],
    ) -> bool:
        """Check if password is not in the password history."""
        for password_hash in password_history:
            try:
                if self._password_validator.verify_password(
                    password,
                    password_hash,
                ):
                    return False
            except UnknownHashError:
                pass

        return True

    async def validate_not_otp_like_suffix(
        self,
        password: str,
        settings: PasswordValidatorSettings,
    ) -> bool:
        """Check if password does not end with a specified number of digits."""
        tail = password[-settings.otp_tail_size :]
        res = tail.isdecimal()
        return not res

    async def validate_min_age(
        self,
        _: str,
        __: Settings,
        min_age_days: int,
        value: str | None,
    ) -> bool:
        """Check if password is older than a specified number of days."""
        if min_age_days == 0:
            return True

        if not value:
            return True

        return (
            self._password_validator.count_password_age_days(value)
            >= min_age_days
        )
