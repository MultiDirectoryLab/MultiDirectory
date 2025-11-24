"""Password Policies data classes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from typing import Generic, Literal, TypeVar

from .constants import PasswordValidatorLanguageType

_IdT = TypeVar("_IdT", int, None)
PriorityT = TypeVar("PriorityT", int, None)


@dataclass(frozen=True)
class DefaultDomainPasswordPolicyPreset:
    """Preset for Default Domain Password Policy configuration."""

    name: str = "Default domain password policy"
    language: Literal["Latin"] = "Latin"

    is_exact_match: Literal[True] = True
    history_length: Literal[4] = 4

    min_age_days: Literal[0] = 0
    max_age_days: Literal[0] = 0

    min_length: Literal[7] = 7
    max_length: Literal[32] = 32

    min_lowercase_letters_count: Literal[0] = 0
    min_uppercase_letters_count: Literal[0] = 0

    min_special_symbols_count: Literal[0] = 0
    min_digits_count: Literal[0] = 0
    min_unique_symbols_count: Literal[0] = 0
    max_repeating_symbols_in_row_count: Literal[0] = 0

    max_sequential_keyboard_symbols_count: Literal[0] = 0
    max_sequential_alphabet_symbols_count: Literal[0] = 0

    max_failed_attempts: Literal[6] = 6
    failed_attempts_reset_sec: Literal[60] = 60
    lockout_duration_sec: Literal[600] = 600
    fail_delay_sec: Literal[5] = 5


@dataclass
class PasswordPolicyDTO(Generic[_IdT, PriorityT]):
    """Password policy data transfer object."""

    group_paths: list[str]

    name: str
    language: PasswordValidatorLanguageType

    is_exact_match: bool
    history_length: int

    min_age_days: int
    max_age_days: int

    min_length: int
    max_length: int

    min_lowercase_letters_count: int
    min_uppercase_letters_count: int

    min_special_symbols_count: int
    min_digits_count: int
    min_unique_symbols_count: int
    max_repeating_symbols_in_row_count: int

    max_sequential_keyboard_symbols_count: int
    max_sequential_alphabet_symbols_count: int

    max_failed_attempts: int
    failed_attempts_reset_sec: int
    lockout_duration_sec: int
    fail_delay_sec: int

    id: _IdT = None  # type: ignore[assignment]
    priority: PriorityT = None  # type: ignore[assignment]
