"""Password Policies data classes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from typing import Generic, Literal, TypeVar

_IdT = TypeVar("_IdT", int, None)
PriorityT = TypeVar("PriorityT", int, None)


@dataclass(frozen=True)
class DefaultDomainPasswordPolicyPreset:
    """Preset for Default Domain Password Policy configuration."""

    name: str = "Default domain password policy"
    history_length: Literal[4] = 4
    min_age_days: Literal[0] = 0
    max_age_days: Literal[0] = 0
    min_length: Literal[7] = 7
    password_must_meet_complexity_requirements: Literal[True] = True


@dataclass(frozen=True)
class TurnoffPasswordPolicyPreset:
    """Preset for turning off Password Policy.

    TurnoffPasswordPolicyPreset is setting all parameters to 0 or False.
    But `name` and `priority` remain unchanged.
    """

    history_length: Literal[0] = 0
    min_age_days: Literal[0] = 0
    max_age_days: Literal[0] = 0
    min_length: Literal[0] = 0
    password_must_meet_complexity_requirements: Literal[False] = False


@dataclass
class PasswordPolicyDTO(Generic[_IdT, PriorityT]):
    """Password policy data transfer object."""

    group_paths: list[str]
    name: str
    history_length: int

    min_age_days: int
    max_age_days: int

    min_length: int

    password_must_meet_complexity_requirements: bool

    id: _IdT = None  # type: ignore[assignment]
    priority: PriorityT = None  # type: ignore[assignment]
