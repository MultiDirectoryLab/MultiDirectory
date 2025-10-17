"""Test Password Policy API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from copy import copy

import pytest
from fastapi import status
from httpx import AsyncClient

from ldap_protocol.policies.password.schemas import PasswordPolicySchema


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
async def test_get_result_policy_for_user(http_client: AsyncClient) -> None:
    """Test get resulting Password Policy for user endpoint."""
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

    user_path = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    response = await http_client.get(
        f"/password-policy/result/{user_path}",
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["name"] == "Test Password Policy"


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_result_policy_for_user_2(http_client: AsyncClient) -> None:
    """Test2 get resulting Password Policy for user endpoint."""
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

    password_policy_schema = PasswordPolicySchema[None, int](
        priority=1,
        name="Test Password Policy2",
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

    password_policy_schema = PasswordPolicySchema[None, int](
        priority=1,
        name="Test Password Policy3",
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

    user_path = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    response = await http_client.get(
        f"/password-policy/result/{user_path}",
    )
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
        json=password_policy_schema.__dict__,
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
async def test_update_priorities(http_client: AsyncClient) -> None:
    """Test update priorities of all password policies endpoint."""
    password_policy_schema = PasswordPolicySchema(
        priority=1,
        name="Test Password Policy 1",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.__dict__,
    )
    assert response.status_code == status.HTTP_201_CREATED

    password_policy_schema = PasswordPolicySchema(
        priority=2,
        name="Test Password Policy 2",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.__dict__,
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
        json=password_policy_schema.__dict__,
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
    assert data["group_paths"] == []
    assert data["password_history_length"] == 0
    assert data["maximum_password_age_days"] == 0
    assert data["minimum_password_age_days"] == 0
    assert data["minimum_password_length"] == 0
    assert data["password_must_meet_complexity_requirements"] is False
