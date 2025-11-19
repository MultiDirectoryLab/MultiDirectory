"""Test Password Policy Service[UseCases].

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import copy

import pytest

from ldap_protocol.policies.password.dataclasses import (
    DefaultDomainPasswordPolicyPreset,
    PasswordPolicyDTO,
)
from ldap_protocol.policies.password.use_cases import PasswordPolicyUseCases

from .datasets import test_get_password_policy_by_dir_path_dn_extended_dataset


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_get_all(password_use_cases: PasswordPolicyUseCases) -> None:
    """Test get all Password Policy endpoint."""
    response = await password_use_cases.get_all()
    assert isinstance(response, list)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_get(password_use_cases: PasswordPolicyUseCases) -> None:
    """Test get one Password Policy endpoint."""
    response = await password_use_cases.get_all()
    assert isinstance(response, list)
    id_ = response[0].id
    dto = await password_use_cases.get(id_)
    assert isinstance(dto, PasswordPolicyDTO)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_get_password_policy_by_dir_path_dn(
    password_use_cases: PasswordPolicyUseCases,
) -> None:
    """Test get Password Policy by directory path endpoint."""
    dto = PasswordPolicyDTO[None, int](
        priority=1,
        group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
        name="Test Password Policy",
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
        min_unique_symbols_count=0,
        max_repeating_symbols_in_row_count=0,
        min_digits_count=0,
        max_sequential_keyboard_symbols_count=0,
        max_sequential_alphabet_symbols_count=0,
        max_failed_attempts=6,
        failed_attempts_reset_sec=60,
        lockout_duration_sec=600,
        fail_delay_sec=5,
    )  # fmt: skip
    await password_use_cases.create(dto)

    policies = await password_use_cases.get_all()
    assert any(policy.name == "Test Password Policy" for policy in policies)

    path_dn = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
    policy = await password_use_cases.get_password_policy_by_dir_path_dn(
        path_dn,
    )
    assert policy.name == "Test Password Policy"


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.parametrize(
    "dataset",
    test_get_password_policy_by_dir_path_dn_extended_dataset,
)
async def test_get_password_policy_by_dir_path_dn_extended(
    dataset: list[PasswordPolicyDTO],
    password_use_cases: PasswordPolicyUseCases,
) -> None:
    """Test get Password Policy by directory path endpoint."""
    for dto in dataset:
        await password_use_cases.create(dto)

    policies = await password_use_cases.get_all()
    assert any(policy.name == "Test Password Policy" for policy in policies)

    path_dn = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
    policy = await password_use_cases.get_password_policy_by_dir_path_dn(
        path_dn,
    )
    assert policy.name == "Test Password Policy3"


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_update(password_use_cases: PasswordPolicyUseCases) -> None:
    """Test update one Password Policy endpoint."""
    dto = PasswordPolicyDTO[None, int](
        priority=1,
        group_paths=[],
        name="Test Password Policy",
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
        min_unique_symbols_count=0,
        max_repeating_symbols_in_row_count=0,
        min_digits_count=0,
        max_sequential_keyboard_symbols_count=0,
        max_sequential_alphabet_symbols_count=0,
        max_failed_attempts=6,
        failed_attempts_reset_sec=60,
        lockout_duration_sec=600,
        fail_delay_sec=5,
    )  # fmt: skip
    await password_use_cases.create(dto)

    policies = await password_use_cases.get_all()
    id_ = next(
        policy.id
        for policy in policies
        if policy.name == "Test Password Policy"
    )

    dto_upd = PasswordPolicyDTO[int, int](
        id=id_,
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
        min_unique_symbols_count=0,
        max_repeating_symbols_in_row_count=0,
        min_digits_count=0,
        max_sequential_keyboard_symbols_count=0,
        max_sequential_alphabet_symbols_count=0,
        max_failed_attempts=6,
        failed_attempts_reset_sec=60,
        lockout_duration_sec=600,
        fail_delay_sec=5,
    )  # fmt: skip
    await password_use_cases.update(id_, dto_upd)

    policies = await password_use_cases.get_all()
    assert any(
        policy.name == "NOT Test Password Policy" for policy in policies
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_reset_domain_policy_to_default_config(
    password_use_cases: PasswordPolicyUseCases,
) -> None:
    """Test reset domain Password Policy to default config endpoint."""
    response = await password_use_cases.get_all()
    policy_data = response[0]

    assert policy_data.history_length == DefaultDomainPasswordPolicyPreset.history_length  # noqa: E501  # fmt: skip
    assert policy_data.min_age_days == DefaultDomainPasswordPolicyPreset.min_age_days  # noqa: E501  # fmt: skip
    assert policy_data.max_age_days == DefaultDomainPasswordPolicyPreset.max_age_days  # noqa: E501  # fmt: skip
    assert policy_data.min_length == DefaultDomainPasswordPolicyPreset.min_length  # noqa: E501  # fmt: skip

    changed_data = copy.deepcopy(policy_data)
    changed_data.min_age_days = 30
    changed_data.max_age_days = 80
    await password_use_cases.update(policy_data.id, changed_data)

    policy = await password_use_cases.get(policy_data.id)
    assert policy.min_age_days == changed_data.min_age_days  # fmt: skip
    assert policy.max_age_days == changed_data.max_age_days  # fmt: skip

    await password_use_cases.reset_domain_policy_to_default_config()

    policy_upd = await password_use_cases.get(policy_data.id)
    assert policy_upd.name == DefaultDomainPasswordPolicyPreset.name
    assert policy_upd.history_length == DefaultDomainPasswordPolicyPreset.history_length  # noqa: E501  # fmt: skip
    assert policy_upd.min_age_days == DefaultDomainPasswordPolicyPreset.min_age_days  # noqa: E501  # fmt: skip
    assert policy_upd.max_age_days == DefaultDomainPasswordPolicyPreset.max_age_days  # noqa: E501  # fmt: skip
    assert policy_upd.min_length == DefaultDomainPasswordPolicyPreset.min_length  # noqa: E501  # fmt: skip
