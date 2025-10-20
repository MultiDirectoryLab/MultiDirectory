"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Generic, Self, TypeVar

from pydantic import BaseModel, Field, model_validator

_IdT = TypeVar("_IdT", int, None)
_PriorityT = TypeVar("_PriorityT", int, None, int | None)


class PasswordPolicySchema(BaseModel, Generic[_IdT, _PriorityT]):
    """PasswordPolicy schema."""

    id: _IdT = None  # type: ignore[assignment]
    priority: _PriorityT = None  # type: ignore[assignment]
    name: str = Field(min_length=3, max_length=255)
    group_paths: list[str] = Field(default_factory=list)
    password_history_length: int = Field(4, ge=0, le=24)
    maximum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_length: int = Field(7, ge=0, le=256)
    password_must_meet_complexity_requirements: bool = True

    @model_validator(mode="after")
    def _validate_priority(self) -> Self:
        if self.priority is not None and self.priority < 1:
            raise ValueError("Priority must be greater than or equal to 1")
        return self

    @model_validator(mode="after")
    def _validate_minimum_pwd_age(self) -> Self:
        if self.minimum_password_age_days > self.maximum_password_age_days:
            raise ValueError(
                "Minimum password age days must be "
                "lower or equal than maximum password age days",
            )
        return self
