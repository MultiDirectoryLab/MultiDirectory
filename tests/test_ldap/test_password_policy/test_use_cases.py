"""Test Password Policy Service[UseCases].

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import copy

import pytest

from ldap_protocol.policies.password.dataclasses import (
    DefaultDomainPasswordPolicyPreset,
    PasswordPolicyDTO,
    TurnoffPasswordPolicyPreset,
)
from ldap_protocol.policies.password.use_case import PasswordPolicyUseCases

from .datasets import (
    test_get_password_policy_by_dir_path_dn_extended_dataset,
    test_update_priorities_dataset,
)


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
async def test_create(password_use_cases: PasswordPolicyUseCases) -> None:
    """Test create one Password Policy endpoint."""
    dto = PasswordPolicyDTO[None, int](
        priority=1,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
    await password_use_cases.create(dto)

    response = await password_use_cases.get_all()
    assert any(policy.name == "Test Password Policy" for policy in response)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_without_priority(
    password_use_cases: PasswordPolicyUseCases,
) -> None:
    """Test create one Password Policy without priority endpoint."""
    dto = PasswordPolicyDTO[None, None](
        priority=None,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
    await password_use_cases.create(dto)

    policies = await password_use_cases.get_all()
    assert any(policy.name == "Test Password Policy" for policy in policies)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_get_password_policy_by_dir_path_dn(
    password_use_cases: PasswordPolicyUseCases,
) -> None:
    """Test get Password Policy by directory path endpoint."""
    dto = PasswordPolicyDTO[None, int](
        priority=1,
        name="Test Password Policy",
        group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
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
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
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
        name="NOT Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
    await password_use_cases.update(id_, dto_upd)

    policies = await password_use_cases.get_all()
    assert any(
        policy.name == "NOT Test Password Policy" for policy in policies
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_delete(password_use_cases: PasswordPolicyUseCases) -> None:
    """Test delete one Password Policy endpoint."""
    dto = PasswordPolicyDTO[None, int](
        priority=1,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )
    await password_use_cases.create(dto)

    policies = await password_use_cases.get_all()
    id_ = next(
        policy.id
        for policy in policies
        if policy.name == "Test Password Policy"
    )
    assert id_ is not None

    await password_use_cases.delete(id_)
    policies = await password_use_cases.get_all()
    assert all(policy.name != "Test Password Policy" for policy in policies)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_reset_domain_policy_to_default_config(
    password_use_cases: PasswordPolicyUseCases,
) -> None:
    """Test reset domain Password Policy to default config endpoint."""
    response = await password_use_cases.get_all()
    policy_data = response[0]

    assert policy_data.password_history_length == DefaultDomainPasswordPolicyPreset.password_history_length  # noqa: E501  # fmt: skip
    assert policy_data.maximum_password_age_days == DefaultDomainPasswordPolicyPreset.maximum_password_age_days  # noqa: E501  # fmt: skip
    assert policy_data.minimum_password_age_days == DefaultDomainPasswordPolicyPreset.minimum_password_age_days  # noqa: E501  # fmt: skip
    assert policy_data.minimum_password_length == DefaultDomainPasswordPolicyPreset.minimum_password_length  # noqa: E501  # fmt: skip
    assert policy_data.password_must_meet_complexity_requirements == DefaultDomainPasswordPolicyPreset.password_must_meet_complexity_requirements  # noqa: E501  # fmt: skip

    changed_data = copy.deepcopy(policy_data)
    changed_data.maximum_password_age_days = 80
    changed_data.minimum_password_age_days = 30
    await password_use_cases.update(policy_data.id, changed_data)

    policy = await password_use_cases.get(policy_data.id)
    assert policy.maximum_password_age_days == changed_data.maximum_password_age_days  # noqa: E501  # fmt: skip
    assert policy.minimum_password_age_days == changed_data.minimum_password_age_days  # noqa: E501  # fmt: skip

    await password_use_cases.reset_domain_policy_to_default_config()

    policy_upd = await password_use_cases.get(policy_data.id)
    assert policy_upd.name == DefaultDomainPasswordPolicyPreset.name
    assert policy_upd.password_history_length == DefaultDomainPasswordPolicyPreset.password_history_length  # noqa: E501  # fmt: skip
    assert policy_upd.maximum_password_age_days == DefaultDomainPasswordPolicyPreset.maximum_password_age_days  # noqa: E501  # fmt: skip
    assert policy_upd.minimum_password_age_days == DefaultDomainPasswordPolicyPreset.minimum_password_age_days  # noqa: E501  # fmt: skip
    assert policy_upd.minimum_password_length == DefaultDomainPasswordPolicyPreset.minimum_password_length  # noqa: E501  # fmt: skip
    assert policy_upd.password_must_meet_complexity_requirements == DefaultDomainPasswordPolicyPreset.password_must_meet_complexity_requirements  # noqa: E501  # fmt: skip


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.parametrize(
    "dataset",
    test_update_priorities_dataset,
)
async def test_update_priorities(
    dataset: list[PasswordPolicyDTO],
    password_use_cases: PasswordPolicyUseCases,
) -> None:
    """Test update priorities of all password policies endpoint."""
    for dto in dataset:
        await password_use_cases.create(dto)

    response = await password_use_cases.get_all()
    id_1 = response[0].id
    id_2 = response[1].id
    id_3 = response[2].id
    assert id_1 is not None
    assert id_2 is not None
    assert id_3 is not None

    await password_use_cases.update_priorities({id_1: 2, id_2: 1, id_3: 3})

    policies = await password_use_cases.get_all()
    for policy in policies:
        if policy.id == id_1:
            assert policy.priority == 2
        elif policy.id == id_2:
            assert policy.priority == 1
        elif policy.id == id_3:
            assert policy.priority == 3


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_turnoff(password_use_cases: PasswordPolicyUseCases) -> None:
    """Test turn off one Password Policy endpoint."""
    dto = PasswordPolicyDTO[None, int](
        priority=1,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )
    await password_use_cases.create(dto)

    response = await password_use_cases.get_all()
    id_ = next(policy.id for policy in response if policy.name == dto.name)
    assert id_ is not None

    await password_use_cases.turnoff(id_)

    policy = await password_use_cases.get(id_)
    assert id_ is not None
    assert policy.id == id_
    assert policy.name == dto.name
    assert policy.priority == dto.priority
    assert policy.group_paths == dto.group_paths
    assert policy.password_history_length == TurnoffPasswordPolicyPreset.password_history_length  # noqa: E501  # fmt: skip
    assert policy.maximum_password_age_days == TurnoffPasswordPolicyPreset.maximum_password_age_days  # noqa: E501  # fmt: skip
    assert policy.minimum_password_age_days == TurnoffPasswordPolicyPreset.minimum_password_age_days  # noqa: E501  # fmt: skip
    assert policy.minimum_password_length == TurnoffPasswordPolicyPreset.minimum_password_length  # noqa: E501  # fmt: skip
    assert policy.password_must_meet_complexity_requirements is TurnoffPasswordPolicyPreset.password_must_meet_complexity_requirements  # noqa: E501  # fmt: skip
