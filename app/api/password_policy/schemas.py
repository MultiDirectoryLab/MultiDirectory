"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Generic, Self, TypeVar

from pydantic import BaseModel, Field, model_validator

from ldap_protocol.policies.password.constants import (
    PasswordValidatorLanguageType,
)
from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAgeDaysError,
    PasswordPolicyPriorityError,
)

_IdT = TypeVar("_IdT", int, None)
PriorityT = TypeVar("PriorityT", int, None)


class PasswordPolicySchema(BaseModel, Generic[_IdT, PriorityT]):
    """Password Policy schema."""

    id: _IdT = None  # type: ignore[assignment]

    group_paths: list[str] = Field(default_factory=list)
    name: str = Field(min_length=3, max_length=255)
    language: PasswordValidatorLanguageType
    priority: PriorityT = None  # type: ignore[assignment]

    is_exact_match: bool
    history_length: int = Field(ge=0, le=24)

    min_age_days: int = Field(ge=0, le=999)
    max_age_days: int = Field(ge=0, le=999)

    min_length: int = Field(ge=6, le=32)
    max_length: int = Field(ge=8, le=256)

    min_lowercase_letters_count: int = Field(ge=0, le=256)
    min_uppercase_letters_count: int = Field(ge=0, le=256)

    min_special_symbols_count: int = Field(ge=0, le=256)
    min_digits_count: int = Field(ge=0, le=256)
    min_unique_symbols_count: int = Field(ge=0, le=256)
    max_repeating_symbols_in_row_count: int = Field(ge=0, le=8)

    max_sequential_keyboard_symbols_count: int = Field(ge=0, le=8)
    max_sequential_alphabet_symbols_count: int = Field(ge=0, le=8)

    max_failed_attempts: int = Field(ge=1, le=100)
    failed_attempts_reset_sec: int = Field(ge=1, le=3600)
    lockout_duration_sec: int = Field(ge=1, le=86400)
    fail_delay_sec: int = Field(ge=0, le=60)

    @model_validator(mode="after")
    def _validate_priority(self) -> Self:
        if self.priority is not None and self.priority < 1:
            raise PasswordPolicyPriorityError(
                "Priority must be greater than or equal to 1",
            )
        return self

    @model_validator(mode="after")
    def _validate_age_days(self) -> Self:
        if self.min_age_days > self.max_age_days:
            raise PasswordPolicyAgeDaysError(
                "Minimum password age days must be "
                "lower or equal than maximum password age days",
            )
        return self

    @model_validator(mode="after")
    def _validate_minimum_pwd_age(self) -> Self:
        if self.min_age_days > self.max_age_days:
            raise ValueError(
                "Minimum password age days must be "
                "less or equal than maximum password age days",
            )
        if self.max_age_days == 0 and self.min_age_days != 0:
            raise ValueError(
                "If max_age_days is 0 (no expiration), min_age_days must "
                "also be 0",
            )
        return self

    @model_validator(mode="after")
    def _validate_minimum_pwd_length(self) -> Self:
        if self.min_length > self.max_length:
            raise ValueError(
                "Minimum password length must be "
                "less or equal than maximum password length",
            )
        min_char_sum = (
            self.min_lowercase_letters_count
            + self.min_uppercase_letters_count
            + self.min_digits_count
            + self.min_special_symbols_count
        )
        if self.min_length < min_char_sum:
            raise ValueError(
                "Minimum password length must be >= sum of required character "
                f"types (current: {self.min_length} < {min_char_sum})",
            )
        return self

    @model_validator(mode="after")
    def _validate_max_length(self) -> Self:
        if (
            self.min_lowercase_letters_count
            + self.min_uppercase_letters_count
            + self.min_special_symbols_count
            + self.min_digits_count
        ) > self.max_length:
            raise ValueError(
                "Sum of required characters must be "
                "less or equal than the maximum password length.",
            )
        return self

    @model_validator(mode="after")
    def _validate_max_repeating_symbols_in_row_count(self) -> Self:
        if self.max_repeating_symbols_in_row_count == 1:
            raise ValueError(
                "Repeating symbols in row count must be "
                "greater than 1 or equal 0.",
            )
        if (
            self.max_repeating_symbols_in_row_count > 0
            and self.max_repeating_symbols_in_row_count > self.min_length
        ):
            raise ValueError(
                "If max_repeating_symbols_in_row_count > 0, "
                "it must be <= min_length",
            )
        return self

    @model_validator(mode="after")
    def _validate_max_sequential_keyboard_symbols_count(self) -> Self:
        if self.max_sequential_keyboard_symbols_count in (1, 2):
            raise ValueError(
                "Max sequential keyboard symbols count must be "
                "greater than 2 or equal 0.",
            )
        if self.max_sequential_keyboard_symbols_count > self.min_length:
            raise ValueError(
                "Max sequential keyboard symbols count must be "
                "less than or equal to the minimum password length.",
            )
        return self

    @model_validator(mode="after")
    def _validate_max_sequential_alphabet_symbols_count(self) -> Self:
        if self.max_sequential_alphabet_symbols_count in (1, 2):
            raise ValueError(
                "Max sequential alphabet symbols count must be "
                "greater than 2 or equal 0.",
            )
        if self.max_sequential_alphabet_symbols_count > self.min_length:
            raise ValueError(
                "Max sequential alphabet symbols count must be "
                "less than or equal to the minimum password length.",
            )
        return self

    @model_validator(mode="after")
    def _validate_min_unique_symbols_count(self) -> Self:
        if self.min_unique_symbols_count > 0:
            min_char_sum = (
                self.min_lowercase_letters_count
                + self.min_uppercase_letters_count
                + self.min_digits_count
                + self.min_special_symbols_count
            )
            if self.min_unique_symbols_count > min_char_sum:
                raise ValueError(
                    "min_unique_symbols_count cannot exceed the sum of all "
                    "required character types",
                )
        return self
