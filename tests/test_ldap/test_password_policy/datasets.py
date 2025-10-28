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
            history_length=5,
            min_age_days=1,
            max_age_days=90,
            min_length=8,
            password_must_meet_complexity_requirements=True,
        ),
        PasswordPolicyDTO[None, int](
            priority=1,
            name="Test Password Policy2",
            group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
            history_length=5,
            min_age_days=1,
            max_age_days=90,
            min_length=8,
            password_must_meet_complexity_requirements=True,
        ),
        PasswordPolicyDTO[None, int](
            priority=1,
            name="Test Password Policy3",
            group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
            history_length=5,
            min_age_days=1,
            max_age_days=90,
            min_length=8,
            password_must_meet_complexity_requirements=True,
        ),
    ],
]

test_update_priorities_dataset = [
    [
        PasswordPolicyDTO(
            group_paths=[],
            name="Test Password Policy 1",
            priority=1,
            history_length=5,
            min_age_days=1,
            max_age_days=90,
            min_length=8,
            password_must_meet_complexity_requirements=True,
        ),
        PasswordPolicyDTO(
            group_paths=[],
            name="Test Password Policy 2",
            priority=2,
            history_length=5,
            min_age_days=1,
            max_age_days=90,
            min_length=8,
            password_must_meet_complexity_requirements=True,
        ),
    ],
]
