"""Datasets for testing Password Policy RestAPI.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

from api.password_policy.schemas import PasswordPolicySchema

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
