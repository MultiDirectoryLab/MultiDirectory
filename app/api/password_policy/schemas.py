"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Generic, Self, TypeVar

from pydantic import BaseModel, Field, model_validator

from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAgeDaysError,
    PasswordPolicyPriorityError,
)

_IdT = TypeVar("_IdT", int, None)
PriorityT = TypeVar("PriorityT", int, None)


class PasswordPolicySchema(BaseModel, Generic[_IdT, PriorityT]):
    """PasswordPolicy schema."""

    id: _IdT = None  # type: ignore[assignment]

    group_paths: list[str] = Field(default_factory=list)
    name: str = Field(min_length=3, max_length=255)
    priority: PriorityT = None  # type: ignore[assignment]

    history_length: int = Field(ge=0, le=24)

    min_age_days: int = Field(ge=0, le=999)
    max_age_days: int = Field(ge=0, le=999)

    min_length: int = Field(ge=0, le=256)

    password_must_meet_complexity_requirements: bool

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
