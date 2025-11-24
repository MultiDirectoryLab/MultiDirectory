"""Datasets for testing Password Policy RestAPI.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

from api.password_policy.schemas import PasswordPolicySchema

test_update_data = [
    PasswordPolicySchema[int](
        id=1,
        priority=2,
        group_paths=[],
        name="NOT Test Password Policy",
        language="Latin",
        is_exact_match=True,
        history_length=5,
        min_age_days=1,
        max_age_days=90,
        min_length=8,
        max_length=32,
        min_lowercase_letters_count=0,
        min_uppercase_letters_count=0,
        min_special_symbols_count=0,
        min_digits_count=0,
        min_unique_symbols_count=0,
        max_repeating_symbols_in_row_count=0,
        max_sequential_keyboard_symbols_count=0,
        max_sequential_alphabet_symbols_count=0,
        max_failed_attempts=1,
        failed_attempts_reset_sec=1,
        lockout_duration_sec=1,
        fail_delay_sec=0,
    ),
]
