"""MultiDirectory Password Validator.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from itertools import islice
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.common_password_dao import CommonPasswordDAO
from ldap_protocol.password_ban_word_dao import PasswordBanWordDAO
from security import count_password_age_days, verify_password

__BASE_KEYBOARD_SEQUENCES: list[str] = [
    "~!@#$%^&*()_+",
    "1234567890",
    "0123456789",
    "`1234567890-=",
    "~1234567890_+",
    "qwertyuiop",
    "qwertyuiop[]\\",
    "qwertyuiop{}|",
    "asdfghjkl",
    "asdfghjkl;'",
    "asdfghjkl:\"",  # noqa: Q003
    "zxcvbnm,./",
    "zxcvbnm<>?",
]  # fmt: skip
_KEYBOARD_SEQUENCES = [v * 2 for v in __BASE_KEYBOARD_SEQUENCES] + [
    v[::-1] * 2 for v in __BASE_KEYBOARD_SEQUENCES
]

__BASE_ALPHABET_SEQUENCES: list[str] = [
    "abcdefghijklmnopqrstuvwxyz",
]
_ALPHABET_SEQUENCES = [v * 2 for v in __BASE_ALPHABET_SEQUENCES] + [
    v[::-1] * 2 for v in __BASE_ALPHABET_SEQUENCES
]


async def min_length(password: str, length: int) -> bool:
    """Validate minimum password length."""
    return len(password) >= length


async def max_length(password: str, length: int) -> bool:
    """Validate maximum password length."""
    return len(password) <= length


async def min_letters_count(password: str, count: int) -> bool:
    """Validate minimum letters count in password."""
    return len(re.findall(r"[a-zA-Z]", password)) >= count


async def min_digits_count(password: str, count: int) -> bool:
    """Validate minimum digits count in password."""
    return len(re.findall(r"\d", password)) >= count


async def min_unique_symbols_count(password: str, count: int) -> bool:
    """Validate minimum unique symbols count in password."""
    return len(set(password)) >= count


async def max_sequential_alphabet_symbols_count(
    password: str, count: int
) -> bool:
    """Validate maximum sequential alphabet symbols count in password.

    Slice lower password and slice alphabet sequences.
    Then check if there is an intersection between two sets of slices.
    If there is an intersection, return False.
    If there is no intersection, return True.
    """
    pwd = password.lower()
    subpwd = set(pwd[i : i + count] for i in range(len(pwd) - count + 1))

    for seq in _ALPHABET_SEQUENCES:
        subseq = set(seq[i : i + count] for i in range(len(seq) - count + 1))
        if subpwd & subseq:
            return False

    return True


async def max_sequential_keyboard_symbols_count(
    password: str, count: int
) -> bool:
    """Validate maximum sequential keyboard symbols count in password.

    Slice lower password and slice keyboard sequences.
    Then check if there is an intersection between two sets of slices.
    If there is an intersection, return False.
    If there is no intersection, return True.
    """
    pwd = password.lower()
    subpwd = set(pwd[i : i + count] for i in range(len(pwd) - count + 1))

    for seq in _KEYBOARD_SEQUENCES:
        subseq = set(seq[i : i + count] for i in range(len(seq) - count + 1))
        if subpwd & subseq:
            return False

    return True


async def max_repeating_symbols_in_row_count(
    password: str, count: int
) -> bool:
    """Validate maximum repeating symbols in row count in password."""
    return not bool(re.findall(rf"(.)\1{{{count - 1}}}+", password))


async def min_special_symbols_count(password: str, count: int) -> bool:
    """Validate minimum special symbols count in password."""
    # Special symbols are defined as non-alphanumeric characters
    return len(re.findall(r"[^a-zA-Z0-9]", password)) >= count


async def min_uppercase_letters_count(password: str, count: int) -> bool:
    """Validate minimum uppercase letters count in password."""
    return len(re.findall(r"[A-Z]", password)) >= count


async def min_lowercase_letters_count(password: str, count: int) -> bool:
    """Validate minimum lowercase letters count in password."""
    return len(re.findall(r"[a-z]", password)) >= count


async def not_contains_in_common_list(
    password: str,
    session: AsyncSession,
) -> bool:
    """Check if password is not in common passwords list."""
    common_password_dao = CommonPasswordDAO(session)
    res = await common_password_dao.get_one_by_password(password)
    return not res


async def not_contain_ban_word(password: str, session: AsyncSession) -> bool:
    """Check if password not contain any banned words."""
    password_ban_word = PasswordBanWordDAO(session)
    res = await password_ban_word.contain_ban_word(password)
    return not res


async def reuse_prevention(
    password: str,
    password_history: list[str],
    history_slice_size: int,
) -> bool:
    """Check if password is not in the password history."""
    password_hashes_chunk = islice(
        reversed(password_history),
        history_slice_size,
    )
    for password_hash in password_hashes_chunk:
        if verify_password(password, password_hash):
            return False
    return True


async def not_otp_like_suffix(password: str, min_digits_count: int) -> bool:
    """Check if password does not end with a specified number of digits."""
    return password[-min_digits_count:].isdecimal() is False


async def min_age(_: Any, min_age_days: int, value: str | None) -> bool:
    """Check if password is older than a specified number of days."""
    if min_age_days == 0:
        return True

    if not value:
        return True

    return count_password_age_days(value) >= min_age_days
