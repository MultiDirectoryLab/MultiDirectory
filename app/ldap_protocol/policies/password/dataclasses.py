"""Password log data classes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from typing import Generic, Literal, TypeVar

_IdT = TypeVar("_IdT", int, None)
_PriorityT = TypeVar("_PriorityT", int, None, int | None)


@dataclass(frozen=True)
class TurnoffPasswordPolicyPreset:
    """Preset for turning off Password Policy."""

    PASSWORD_HISTORY_LENGTH: Literal[0] = 0
    MAXIMUM_PASSWORD_AGE_DAYS: Literal[0] = 0
    MINIMUM_PASSWORD_AGE_DAYS: Literal[0] = 0
    MINIMUM_PASSWORD_LENGTH: Literal[0] = 0
    PASSWORD_MUST_MEET_COMPLEXITY_REQUIREMENTS: Literal[False] = False


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
