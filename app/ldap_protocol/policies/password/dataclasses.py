"""Password log data classes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar

_IdT = TypeVar("_IdT", int, None)
_PriorityT = TypeVar("_PriorityT", int, None, int | None)


class TurnoffPasswordPolicyPreset(Enum):
    PASSWORD_HISTORY_LENGTH = 0
    MAXIMUM_PASSWORD_AGE_DAYS = 0
    MINIMUM_PASSWORD_AGE_DAYS = 0
    MINIMUM_PASSWORD_LENGTH = 0
    PASSWORD_MUST_MEET_COMPLEXITY_REQUIREMENTS = False


@dataclass
class PasswordPolicyPriorityUpdateDTO:
    """DTO for updating priorities of Password Policies."""

    priorities: dict[int, int]


@dataclass
class PasswordPolicyDTO(Generic[_IdT, _PriorityT]):
    """Password policy data transfer object."""

    name: str
    group_paths: list[str]
    password_history_length: int
    maximum_password_age_days: int
    minimum_password_age_days: int
    minimum_password_length: int
    password_must_meet_complexity_requirements: bool
    id: _IdT = None  # type: ignore[assignment]
    priority: _PriorityT = None  # type: ignore[assignment]
