"""Utils for Password Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime, timezone

from passlib.context import CryptContext

from ldap_protocol.utils.helpers import ft_to_dt

__crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Validate password.

    :param str plain_password: raw password
    :param str hashed_password: pwd hash from db
    :return bool: is password verified
    """
    return __crypt_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password.

    :param str password: raw pwd
    :return str: hash
    """
    return __crypt_context.hash(password, max_rounds=9)


def count_password_age_days(win_filetime: str | None) -> int:
    """Get number of days after Windows filetime."""
    tz = timezone.utc

    now_dt = datetime.now(tz=tz)
    value_dt = (
        ft_to_dt(int(win_filetime)).astimezone(tz)
        if win_filetime
        else now_dt
    )  # fmt: skip

    return (now_dt - value_dt).days
