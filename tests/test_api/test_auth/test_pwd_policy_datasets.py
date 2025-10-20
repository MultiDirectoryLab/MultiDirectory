"""Datasets for test Password Policy API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

from api.password_policy.schemas import PasswordPolicySchema

test_get_policy_by_dir_path_extended_dataset = [
    [
        PasswordPolicySchema[None, int](
            priority=1,
            name="Test Password Policy",
            group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
            password_history_length=5,
            maximum_password_age_days=90,
            minimum_password_age_days=1,
            minimum_password_length=8,
            password_must_meet_complexity_requirements=True,
        ),
        PasswordPolicySchema[None, int](
            priority=1,
            name="Test Password Policy2",
            group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
            password_history_length=5,
            maximum_password_age_days=90,
            minimum_password_age_days=1,
            minimum_password_length=8,
            password_must_meet_complexity_requirements=True,
        ),
        PasswordPolicySchema[None, int](
            priority=1,
            name="Test Password Policy3",
            group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
            password_history_length=5,
            maximum_password_age_days=90,
            minimum_password_age_days=1,
            minimum_password_length=8,
            password_must_meet_complexity_requirements=True,
        ),
    ],
]

test_update_priorities_dataset = [
    [
        PasswordPolicySchema(
            priority=1,
            name="Test Password Policy 1",
            group_paths=[],
            password_history_length=5,
            maximum_password_age_days=90,
            minimum_password_age_days=1,
            minimum_password_length=8,
            password_must_meet_complexity_requirements=True,
        ),
        PasswordPolicySchema(
            priority=2,
            name="Test Password Policy 2",
            group_paths=[],
            password_history_length=5,
            maximum_password_age_days=90,
            minimum_password_age_days=1,
            minimum_password_length=8,
            password_must_meet_complexity_requirements=True,
        ),
    ],
]
