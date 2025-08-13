"""Checks for Password Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any, Iterable

from passlib.exc import UnknownHashError

from .settings import _PasswordValidatorSettings
from .utils import count_password_age_days, verify_password


async def min_length(password: str, _: Any, length: int) -> bool:
    """Validate minimum password length."""
    return len(password) >= length


async def reuse_prevention(
    password: str,
    _: Any,
    password_history: Iterable[str],
) -> bool:
    """Check if password is not in the password history."""
    for password_hash in password_history:
        try:
            if verify_password(password, password_hash):
                return False
        except UnknownHashError:
            pass

    return True


async def not_otp_like_suffix(
    password: str,
    settings: _PasswordValidatorSettings,
) -> bool:
    """Check if password does not end with a specified number of digits."""
    tail = password[-settings.otp_tail_size :]
    res = tail.isdecimal()
    return not res


async def min_age(
    _: Any,
    __: Any,
    min_age_days: int,
    value: str | None,
) -> bool:
    """Check if password is older than a specified number of days."""
    if min_age_days == 0:
        return True

    if not value:
        return True

    return count_password_age_days(value) >= min_age_days
