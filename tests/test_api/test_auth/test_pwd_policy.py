"""Test Password Policy API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from copy import copy

import pytest
from fastapi import status
from httpx import AsyncClient

from api.password_policy.schemas import PasswordPolicySchema
from ldap_protocol.policies.password.dataclasses import (
    DefaultDomainPasswordPolicyPreset,
    TurnoffPasswordPolicyPreset,
)

from .test_pwd_policy_datasets import (
    test_get_policy_by_dir_path_extended_dataset,
    test_update_priorities_dataset,
)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_all(http_client: AsyncClient) -> None:
    """Test get all Password Policy endpoint."""
    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert isinstance(data[0], dict)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get(http_client: AsyncClient) -> None:
    """Test get one Password Policy endpoint."""
    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    response = await http_client.get(f"/password-policy/{data[0]['id']}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == data[0]["id"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create(http_client: AsyncClient) -> None:
    """Test create one Password Policy endpoint."""
    password_policy_schema = PasswordPolicySchema[None, int](
        priority=1,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert any(policy["name"] == "Test Password Policy" for policy in data)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_without_priority(http_client: AsyncClient) -> None:
    """Test create one Password Policy without priority endpoint."""
    password_policy_schema = PasswordPolicySchema[None, None](
        priority=None,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert any(policy["name"] == "Test Password Policy" for policy in data)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_policy_by_dir_path(
    http_client: AsyncClient,
) -> None:
    """Test get Password Policy by directory path endpoint."""
    password_policy_schema = PasswordPolicySchema[None, int](
        priority=1,
        name="Test Password Policy",
        group_paths=["cn=developers,cn=groups,dc=md,dc=test"],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert any(policy["name"] == "Test Password Policy" for policy in data)

    path = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
    response = await http_client.get(f"/password-policy/by_dir_path/{path}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["name"] == "Test Password Policy"


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize(
    "dataset",
    test_get_policy_by_dir_path_extended_dataset,
)
async def test_get_policy_by_dir_path_extended(
    dataset: list[PasswordPolicySchema],
    http_client: AsyncClient,
) -> None:
    """Test get Password Policy by directory path endpoint."""
    for password_policy_schema in dataset:
        response = await http_client.post(
            "/password-policy",
            json=password_policy_schema.model_dump(),
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert any(policy["name"] == "Test Password Policy" for policy in data)

    path = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
    response = await http_client.get(f"/password-policy/by_dir_path/{path}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["name"] == "Test Password Policy3"


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_update(http_client: AsyncClient) -> None:
    """Test update one Password Policy endpoint."""
    password_policy_schema = PasswordPolicySchema[None, int](
        priority=1,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    id_ = next(
        policy["id"]
        for policy in data
        if policy["name"] == "Test Password Policy"
    )

    password_policy_schema_upd = PasswordPolicySchema[int, int](
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
    response = await http_client.put(
        f"/password-policy/{id_}",
        json=password_policy_schema_upd.model_dump(),
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete(http_client: AsyncClient) -> None:
    """Test delete one Password Policy endpoint."""
    password_policy_schema = PasswordPolicySchema(
        priority=1,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    id_ = next(
        policy["id"]
        for policy in data
        if policy["name"] == "Test Password Policy"
    )
    assert id_ is not None

    response = await http_client.delete(f"/password-policy/{id_}")
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert all(policy["name"] != "Test Password Policy" for policy in data)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_reset_domain_policy_to_default_config(
    http_client: AsyncClient,
) -> None:
    """Test reset domain Password Policy to default config endpoint."""
    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    policy_data = data[0]

    assert policy_data["name"] == DefaultDomainPasswordPolicyPreset.DOMAIN_PASSWORD_POLICY_NAME  # noqa: E501  # fmt: skip
    assert policy_data["password_history_length"] == DefaultDomainPasswordPolicyPreset.PASSWORD_HISTORY_LENGTH  # noqa: E501  # fmt: skip
    assert policy_data["maximum_password_age_days"] == DefaultDomainPasswordPolicyPreset.MAXIMUM_PASSWORD_AGE_DAYS  # noqa: E501  # fmt: skip
    assert policy_data["minimum_password_age_days"] == DefaultDomainPasswordPolicyPreset.MINIMUM_PASSWORD_AGE_DAYS  # noqa: E501  # fmt: skip
    assert policy_data["minimum_password_length"] == DefaultDomainPasswordPolicyPreset.MINIMUM_PASSWORD_LENGTH  # noqa: E501  # fmt: skip
    assert policy_data["password_must_meet_complexity_requirements"] == DefaultDomainPasswordPolicyPreset.PASSWORD_MUST_MEET_COMPLEXITY_REQUIREMENTS  # noqa: E501  # fmt: skip

    changed_data = copy(policy_data)
    changed_data["maximum_password_age_days"] = 80
    changed_data["minimum_password_age_days"] = 30
    response = await http_client.put(
        f"/password-policy/{policy_data['id']}",
        json=changed_data,
    )
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(f"/password-policy/{policy_data['id']}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == changed_data

    response = await http_client.put(
        "/password-policy/reset/domain_policy_to_default_config",
    )
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(f"/password-policy/{policy_data['id']}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == policy_data


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize(
    "dataset",
    test_update_priorities_dataset,
)
async def test_update_priorities(
    dataset: list[PasswordPolicySchema],
    http_client: AsyncClient,
) -> None:
    """Test update priorities of all password policies endpoint."""
    for password_policy_schema in dataset:
        response = await http_client.post(
            "/password-policy",
            json=password_policy_schema.model_dump(),
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    id_1 = data[0]["id"]
    id_2 = data[1]["id"]
    id_3 = data[2]["id"]
    assert id_1 is not None
    assert id_2 is not None
    assert id_3 is not None

    response = await http_client.put(
        "/password-policy/update/priorities",
        json={id_1: 2, id_2: 1, id_3: 3},
    )
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    for policy in data:
        if policy["id"] == id_1:
            assert policy["priority"] == 2
        elif policy["id"] == id_2:
            assert policy["priority"] == 1
        elif policy["id"] == id_3:
            assert policy["priority"] == 3


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_turnoff(http_client: AsyncClient) -> None:
    """Test turn off one Password Policy endpoint."""
    password_policy_schema = PasswordPolicySchema(
        priority=1,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    id_ = next(
        policy["id"]
        for policy in data
        if policy["name"] == password_policy_schema.name
    )
    assert id_ is not None

    response = await http_client.put(f"/password-policy/turnoff/{id_}")
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(f"/password-policy/{id_}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == id_
    assert data["name"] == password_policy_schema.name
    assert data["priority"] == password_policy_schema.priority
    assert data["group_paths"] == password_policy_schema.group_paths
    assert data["password_history_length"] == TurnoffPasswordPolicyPreset.PASSWORD_HISTORY_LENGTH  # noqa: E501  # fmt: skip
    assert data["maximum_password_age_days"] == TurnoffPasswordPolicyPreset.MAXIMUM_PASSWORD_AGE_DAYS  # noqa: E501  # fmt: skip
    assert data["minimum_password_age_days"] == TurnoffPasswordPolicyPreset.MINIMUM_PASSWORD_AGE_DAYS  # noqa: E501  # fmt: skip
    assert data["minimum_password_length"] == TurnoffPasswordPolicyPreset.MINIMUM_PASSWORD_LENGTH  # noqa: E501  # fmt: skip
    assert data["password_must_meet_complexity_requirements"] is TurnoffPasswordPolicyPreset.PASSWORD_MUST_MEET_COMPLEXITY_REQUIREMENTS  # noqa: E501  # fmt: skip
