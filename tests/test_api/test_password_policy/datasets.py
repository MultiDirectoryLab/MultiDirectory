"""Datasets for testing Password Policy RestAPI.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

from api.password_policy.schemas import PasswordPolicySchema

test_create_data = [
    PasswordPolicySchema[None, int](
        priority=1,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    ),
]

test_create_without_priority_data = [
    PasswordPolicySchema[None, None](
        priority=None,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    ),
]

test_update_data = [
    PasswordPolicySchema[int, int](
        id=1,
        priority=2,
        name="NOT Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    ),
]
