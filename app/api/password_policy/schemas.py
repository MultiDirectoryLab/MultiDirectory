"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from pydantic import BaseModel, Field, model_validator


class PasswordPolicySchema(BaseModel):
    """PasswordPolicy schema."""

    name: str = Field(
        "Default domain password policy",
        min_length=3,
        max_length=255,
    )
    password_history_length: int = Field(4, ge=0, le=24)
    maximum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_length: int = Field(7, ge=0, le=256)
    password_must_meet_complexity_requirements: bool = True

    @model_validator(mode="after")
    def _validate_minimum_pwd_age(self) -> "PasswordPolicySchema":
        if self.minimum_password_age_days > self.maximum_password_age_days:
            raise ValueError(
                "Minimum password age days must be "
                "lower or equal than maximum password age days",
            )
        return self
