"""
Test Access Policy service.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

test_access_policies_sets = [
    {
        "name": "policy_1",
        "can_read": True,
        "can_add": False,
        "can_modify": False,
        "can_delete": False,
        "groups": ["cn=group1,ou=groups,dc=md,dc=test-localhost"],
    },
    {
        "name": "policy_2",
        "can_read": False,
        "can_add": True,
        "can_modify": True,
        "can_delete": False,
        "groups": ["cn=group2,ou=groups,dc=md,dc=test-localhost"],
    },
]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize("policy", test_access_policies_sets)
async def test_create_access_policy(
    unbound_http_client: AsyncClient,
    session: AsyncSession,
    policy: dict,
) -> None:
    """Test creating a new access policy."""
    response = await unbound_http_client.post(
        "/access_policy",
        json=policy,
    )
    assert response.status_code == status.HTTP_201_CREATED

    data = response.json()
    assert data["name"] == policy["name"]
    assert data["can_read"] == policy["can_read"]
    assert data["can_add"] == policy["can_add"]
    assert data["can_modify"] == policy["can_modify"]
    assert data["can_delete"] == policy["can_delete"]
    assert data["groups"] == policy["groups"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_clone_access_policy(
    unbound_http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test cloning an existing access policy."""
    # First, create an access policy to clone
    response_1 = await unbound_http_client.post(
        "/access_policy",
        json={
            "name": "original_access_policy",
            "can_read": True,
            "can_add": False,
            "can_modify": False,
            "can_delete": False,
            "groups": ["cn=original_group,ou=groups,dc=md,dc=test-localhost"],
        },
    )
    assert response_1.status_code == status.HTTP_201_CREATED
    original_ap = response_1.json()  # TODO FIXME это не должно быть здесь, наружу вынеси

    # Second, clone the created access policy
    response_2 = await unbound_http_client.post(
        "/access_policy/clone",
        json={
            "access_policy_id": original_ap["id"],
            "grant_dn": "cn=cloned_policy,ou=groups,dc=md,dc=test-localhost",
        },
    )
    assert response_2.status_code == status.HTTP_201_CREATED

    cloned_ap = response_2.json()
    assert cloned_ap["name"] == original_ap["name"]
    assert cloned_ap["can_read"] == original_ap["can_read"]
    assert cloned_ap["can_add"] == original_ap["can_add"]
    assert cloned_ap["can_modify"] == original_ap["can_modify"]
    assert cloned_ap["can_delete"] == original_ap["can_delete"]
    assert cloned_ap["groups"] == original_ap["groups"]


test_access_policies_sets = [
    {
        "name": "policy_1",
        "can_read": True,
        "can_add": False,
        "can_modify": False,
        "can_delete": False,
        "groups": ["cn=group1,ou=groups,dc=md,dc=test-localhost"],
    },
    {
        "name": "policy_2",
        "can_read": False,
        "can_add": True,
        "can_modify": True,
        "can_delete": False,
        "groups": ["cn=group2,ou=groups,dc=md,dc=test-localhost"],
    },
]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize("policy", test_access_policies_sets)
async def test_get_access_policy(
    unbound_http_client: AsyncClient,
    session: AsyncSession,
    policy: dict,
) -> None:
    """Test retrieving an existing access policy."""
    # First, create an access policy to retrieve
    create_response = await unbound_http_client.post("/access_policy", json=policy)
    assert create_response.status_code == status.HTTP_201_CREATED
    created_policy = create_response.json()

    # Now, retrieve the created access policy
    get_response = await unbound_http_client.get(f"/access_policy/{created_policy['id']}")
    assert get_response.status_code == status.HTTP_200_OK

    retrieved_policy = get_response.json()
    assert retrieved_policy["name"] == created_policy["name"]
    assert retrieved_policy["can_read"] == created_policy["can_read"]
    assert retrieved_policy["can_add"] == created_policy["can_add"]
    assert retrieved_policy["can_modify"] == created_policy["can_modify"]
    assert retrieved_policy["can_delete"] == created_policy["can_delete"]
    assert retrieved_policy["groups"] == created_policy["groups"]


test_access_policies_sets = [
    [
        {
            "name": "policy_1",
            "can_read": True,
            "can_add": False,
            "can_modify": False,
            "can_delete": False,
            "groups": ["cn=group1,ou=groups,dc=md,dc=test-localhost"],
        },
        {
            "name": "policy_2",
            "can_read": False,
            "can_add": True,
            "can_modify": True,
            "can_delete": False,
            "groups": ["cn=group2,ou=groups,dc=md,dc=test-localhost"],
        },
    ],
    [
        {
            "name": "policy_3",
            "can_read": True,
            "can_add": True,
            "can_modify": False,
            "can_delete": True,
            "groups": ["cn=group3,ou=groups,dc=md,dc=test-localhost"],
        },
        {
            "name": "policy_4",
            "can_read": False,
            "can_add": False,
            "can_modify": True,
            "can_delete": True,
            "groups": ["cn=group4,ou=groups,dc=md,dc=test-localhost"],
        },
    ],
]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize("policies", test_access_policies_sets)
async def test_get_access_policies(
    unbound_http_client: AsyncClient,
    session: AsyncSession,
    policies: list,
) -> None:
    """Test retrieving all access policies."""
    # Create access policies
    for policy in policies:
        response = await unbound_http_client.post("/access_policy", json=policy)
        assert response.status_code == status.HTTP_201_CREATED

    # Retrieve all access policies
    get_response = await unbound_http_client.get("/access_policy")
    assert get_response.status_code == status.HTTP_200_OK

    retrieved_policies = get_response.json()
    assert len(retrieved_policies) == len(policies)

    for i, policy in enumerate(policies):
        assert retrieved_policies[i]["name"] == policy["name"]
        assert retrieved_policies[i]["can_read"] == policy["can_read"]
        assert retrieved_policies[i]["can_add"] == policy["can_add"]
        assert retrieved_policies[i]["can_modify"] == policy["can_modify"]
        assert retrieved_policies[i]["can_delete"] == policy["can_delete"]
        assert retrieved_policies[i]["groups"] == policy["groups"]


# TODO FIXME сделай тут parametrize
test_access_policy = {
    "name": "policy_to_modify",
    "can_read": True,
    "can_add": False,
    "can_modify": False,
    "can_delete": False,
    "groups": ["cn=group1,ou=groups,dc=md,dc=test-localhost"],
}

modified_access_policy = {
    "name": "modified_policy",
    "can_read": False,
    "can_add": True,
    "can_modify": True,
    "can_delete": True,
    "groups": ["cn=group2,ou=groups,dc=md,dc=test-localhost"],
}


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_modify_access_policy(
    unbound_http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test modifying an existing access policy."""
    # First, create an access policy to modify
    create_response = await unbound_http_client.post("/access_policy", json=test_access_policy)
    assert create_response.status_code == status.HTTP_201_CREATED
    created_policy = create_response.json()

    # Now, modify the created access policy
    modify_response = await unbound_http_client.patch(
        f"/access_policy/{created_policy['id']}",
        json=modified_access_policy,
    )
    assert modify_response.status_code == status.HTTP_200_OK

    modified_policy = modify_response.json()
    assert modified_policy["name"] == modified_access_policy["name"]
    assert modified_policy["can_read"] == modified_access_policy["can_read"]
    assert modified_policy["can_add"] == modified_access_policy["can_add"]
    assert modified_policy["can_modify"] == modified_access_policy["can_modify"]
    assert modified_policy["can_delete"] == modified_access_policy["can_delete"]
    assert modified_policy["groups"] == modified_access_policy["groups"]


test_access_policies_to_delete = [
    {
        "name": "policy_to_delete_1",
        "can_read": True,
        "can_add": False,
        "can_modify": False,
        "can_delete": False,
        "groups": ["cn=group1,ou=groups,dc=md,dc=test-localhost"],
    },
    {
        "name": "policy_to_delete_2",
        "can_read": False,
        "can_add": True,
        "can_modify": True,
        "can_delete": False,
        "groups": ["cn=group2,ou=groups,dc=md,dc=test-localhost"],
    },
]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize("policy", test_access_policies_to_delete)
async def test_delete_access_policies(
    unbound_http_client: AsyncClient,
    session: AsyncSession,
    policy: dict,
) -> None:
    """Test deleting multiple access policies."""
    # Create access policy to delete
    response = await unbound_http_client.post("/access_policy", json=policy)
    assert response.status_code == status.HTTP_201_CREATED
    policy_id = response.json()["id"]

    # Delete the created access policy
    delete_response = await unbound_http_client.delete(
        "/access_policy/bulk",
        json={"access_policy_ids": [policy_id]},
    )
    assert delete_response.status_code == status.HTTP_204_NO_CONTENT

    # Verify the access policy has been deleted
    get_response = await unbound_http_client.get(f"/access_policy/{policy_id}")
    assert get_response.status_code == status.HTTP_404_NOT_FOUND


test_access_policy = [
    {
        "name": "policy_to_attach2",
        "can_read": True,
        "can_add": False,
        "can_modify": False,
        "can_delete": False,
        "groups": ["cn=group1,ou=groups,dc=md,dc=test-localhost"],
    },
    {
        "name": "policy_to_attach2",
        "can_read": True,
        "can_add": False,
        "can_modify": True,
        "can_delete": True,
        "groups": ["cn=group2,ou=groups,dc=md,dc=test-localhost"],
    },
]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize("policy", test_access_policies_to_delete)
async def test_attach_access_policy_to_group(
    unbound_http_client: AsyncClient,
    session: AsyncSession,
    policy: dict,
) -> None:
    """Test attaching an access policy to a group."""
    # First, create an access policy to attach
    create_response = await unbound_http_client.post("/access_policy", json=policy)
    assert create_response.status_code == status.HTTP_201_CREATED
    created_policy = create_response.json()

    # Attach the created access policy to groups
    attach_response = await unbound_http_client.post(
        "/access_policy/attach",
        json={
            "access_policy_id": created_policy["id"],
            "group_dn": "cn=test_group1,ou=groups,dc=md,dc=test-localhost",
        },
    )
    assert attach_response.status_code == status.HTTP_200_OK

    attached_policy = attach_response.json()
    assert attached_policy["id"] == created_policy["id"]
    assert "cn=test_group1,ou=groups,dc=md,dc=test-localhost" in attached_policy["groups"]
