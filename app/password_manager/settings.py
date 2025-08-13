"""Password Validator Settings.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

_REGEXP_DIGITS: str = r"\d"


class _PasswordValidatorSettings:
    """Password Validator Settings."""

    otp_tail_size: Literal[6] = 6
