"""Password Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Iterable, Self

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
    """Builder for password validation rules.

    This class accumulates checks and validates a password against them.
    """

    def __init__(self) -> None:
        """Initialize a new validator instance.

        Sets up internal storage for checkers and default settings.
        """
        self.__checkers: list[_Checker] = []
        self.__settings: _PasswordValidatorSettings = (
            _PasswordValidatorSettings()
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
        """Validate the given password against the configured schema.

        Runs all registered checks and collects error messages.

        :param str password: Password to validate.
        :return: bool.

        :Example:
            .. code-block:: python

                assert not await (
                    PasswordValidator()
                    .min_length(3)
                    .validate("13")
                )
                assert await PasswordValidator().min_length(3).validate("abc")
        """  # fmt: skip
        self.error_messages = []
        for checker in self.__checkers:
            await self.__run_checker(checker, password)

        return not bool(self.error_messages)

    def min_length(self, length: int) -> Self:
        """Require minimum password length.

        :param int length: Minimal allowed length.
        :return: PasswordValidator.

        :Example:
            .. code-block:: python

                assert await (
                    PasswordValidator()
                    .min_length(8)
                    .validate("testPassword")
                )
                assert not await (
                    PasswordValidator()
                    .min_length(8)
                    .validate("test")
                )
        """  # fmt: skip
        self.__add_checker(
            check=checks.min_length,
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

        :return: PasswordValidator.
        """
        self.__add_checker(
            check=checks.reuse_prevention,
            error_message=ErrorMessages.NOT_IN_HISTORY,
            args=[password_history],
        )
        return self

    def not_otp_like_suffix(self) -> Self:
        """Forbid an OTP-like numeric suffix of configured length.

        :return: PasswordValidator.

        :Example:
            .. code-block:: python

                assert not await (
                    PasswordValidator()
                    .not_otp_like_suffix()
                    .validate("test123456")
                )
                assert await (
                    PasswordValidator()
                    .not_otp_like_suffix()
                    .validate("test12345")
                )
        """  # fmt: skip
        self.__add_checker(
            check=checks.not_otp_like_suffix,
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

        :param int min_age_days: Minimal age in days to allow update.
        :param str | None value: Windows filetime string representing last
        change, or ``None``.
        :return: PasswordValidator.

        :Note:
            If ``min_age_days`` is ``0`` or ``value`` is ``None``,
            the check passes.
        """
        self.__add_checker(
            check=checks.min_age,
            error_message=ErrorMessages.NOT_OLD_ENOUGH,
            args=[min_age_days, value],
        )
        return self
