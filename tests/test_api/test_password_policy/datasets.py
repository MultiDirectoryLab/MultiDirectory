"""Datasets for testing Password Policy RestAPI.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

from api.password_policy.schemas import PasswordPolicySchema

test_create_data = [
    PasswordPolicySchema[None, int](
        group_paths=[],
        name="Test Password Policy",
        priority=1,
        history_length=5,
        min_age_days=1,
        max_age_days=90,
        min_length=8,
        password_must_meet_complexity_requirements=True,
    ),
]

test_create_without_priority_data = [
    PasswordPolicySchema[None, None](
        group_paths=[],
        name="Test Password Policy",
        priority=None,
        history_length=5,
        min_age_days=1,
        max_age_days=90,
        min_length=8,
        password_must_meet_complexity_requirements=True,
    ),
]

test_update_data = [
    PasswordPolicySchema[int, int](
        id=1,
        group_paths=[],
        name="NOT Test Password Policy",
        priority=2,
        history_length=5,
        min_age_days=1,
        max_age_days=90,
        min_length=8,
        password_must_meet_complexity_requirements=True,
    ),
]
