"""Datasets for testing Password Policy Service[UseCases].

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

from ldap_protocol.policies.password.dataclasses import PasswordPolicyDTO

test_get_password_policy_by_dir_path_dn_extended_dataset = [
    [
        PasswordPolicyDTO[None, int](
            priority=1,
            name="Test Password Policy",
            group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
            password_history_length=5,
            maximum_password_age_days=90,
            minimum_password_age_days=1,
            minimum_password_length=8,
            password_must_meet_complexity_requirements=True,
        ),
        PasswordPolicyDTO[None, int](
            priority=1,
            name="Test Password Policy2",
            group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
            password_history_length=5,
            maximum_password_age_days=90,
            minimum_password_age_days=1,
            minimum_password_length=8,
            password_must_meet_complexity_requirements=True,
        ),
        PasswordPolicyDTO[None, int](
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
        PasswordPolicyDTO(
            priority=1,
            name="Test Password Policy 1",
            group_paths=[],
            password_history_length=5,
            maximum_password_age_days=90,
            minimum_password_age_days=1,
            minimum_password_length=8,
            password_must_meet_complexity_requirements=True,
        ),
        PasswordPolicyDTO(
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
