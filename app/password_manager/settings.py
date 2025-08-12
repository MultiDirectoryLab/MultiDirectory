"""Password Validator Settings.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

_REGEXP_DIGITS: str = r"\d"


class _PasswordValidatorSettings:
    """Password Validator Settings."""

    otp_tail_size: Literal[6] = 6
    alphabet_sequence: str
    keyboard_sequences: list[str]
    regexp_letters: str
    regexp_digits: str = _REGEXP_DIGITS
    regexp_not_valid_letters: str
    regexp_special_symbols: str
    regexp_uppercase_letters: str
    regexp_lowercase_letters: str
