"""Audit log data classes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass


@dataclass
class PasswordPolicyDTO:
    """Password policy data transfer object."""

    name: str
    history_length: int
    max_age_days: int
    min_age_days: int
    min_length: int
    password_must_meet_complexity_requirements: bool


@dataclass
class PasswordPolicyResponse:
    """Password policy response object."""

    name: str
    history_length: int
    max_age_days: int
    min_age_days: int
    min_length: int
    password_must_meet_complexity_requirements: bool
