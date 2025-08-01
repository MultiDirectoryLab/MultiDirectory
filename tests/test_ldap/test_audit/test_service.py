"""Test audit service.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
import pytest_asyncio

from ldap_protocol.policies.audit.dataclasses import (
    AuditDestinationDTO,
    AuditPolicyDTO,
)
from ldap_protocol.policies.audit.enums import (
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
)
from ldap_protocol.policies.audit.exception import (
    AuditAlreadyExistsError,
    AuditNotFoundError,
)
from ldap_protocol.policies.audit.service import AuditService


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_update_audit_policy(
    audit_service: AuditService,
) -> None:
    """Test updating an audit policy."""
    old_policy = (await audit_service.get_policies())[0]

    new_policy_id = 999999
    new_policy = AuditPolicyDTO(
        id=new_policy_id,
        name="Test Policy",
        is_enabled=True,
        severity=old_policy.severity,
    )

    await audit_service.update_policy(old_policy.id, new_policy)

    for policy in await audit_service.get_policies():
        if policy.id == new_policy_id:
            assert policy == new_policy
            break
    else:
        pytest.fail(
            f"Policy with id {new_policy_id} not found in updated policies.",
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_update_audit_policy_with_existing_id(
    audit_service: AuditService,
) -> None:
    """Test updating an audit policy."""
    first_policy, second_policy = (await audit_service.get_policies())[:2]

    new_policy_id = second_policy.id
    new_policy = AuditPolicyDTO(
        id=new_policy_id,
        name="Test Policy",
        is_enabled=True,
        severity=first_policy.severity,
    )

    with pytest.raises(
        AuditAlreadyExistsError,
        match="Audit policy already exists",
    ):
        await audit_service.update_policy(first_policy.id, new_policy)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_update_audit_policy_with_non_existing_id(
    audit_service: AuditService,
) -> None:
    """Test updating an audit policy."""
    latest_policy = (await audit_service.get_policies())[-1]

    new_policy_id = latest_policy.id + 2
    new_policy = AuditPolicyDTO(
        id=new_policy_id,
        name="Test Policy",
        is_enabled=True,
        severity=latest_policy.severity,
    )

    with pytest.raises(
        AuditNotFoundError,
        match=f"Policy with id {latest_policy.id + 1} not found.",
    ):
        await audit_service.update_policy(latest_policy.id + 1, new_policy)


@pytest_asyncio.fixture(scope="function")
@pytest.mark.usefixtures("setup_session")
async def audit_destination(
    audit_service: AuditService,
) -> AuditDestinationDTO:
    """Fixture to provide an audit destination."""
    new_destination = AuditDestinationDTO(
        name="Test Destination",
        service_type=AuditDestinationServiceType.SYSLOG,
        host="localhost",
        port=1234,
        protocol=AuditDestinationProtocolType.TCP,
        is_enabled=True,
    )
    await audit_service.create_destination(new_destination)
    destinations = await audit_service.get_destinations()

    destination = next(
        (dest for dest in destinations if dest.name == new_destination.name),
        None,
    )
    assert destination is not None, "Destination was not created successfully."

    return destination


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_update_audit_destination(
    audit_service: AuditService,
    audit_destination: AuditDestinationDTO,
) -> None:
    """Test updating an audit destination."""
    updated_destination = AuditDestinationDTO(
        id=audit_destination.id,
        name="Updated Destination",
        service_type=AuditDestinationServiceType.SYSLOG,
        host="updated.example.com",
        port=5678,
        protocol=AuditDestinationProtocolType.UDP,
        is_enabled=False,
    )

    assert audit_destination.id is not None, "Destination ID is None."

    await audit_service.update_destination(
        audit_destination.id,
        updated_destination,
    )

    for destination in await audit_service.get_destinations():
        if destination.name == updated_destination.name:
            assert destination == updated_destination
            break
    else:
        pytest.fail("Destination not updated correctly.")


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_delete_audit_destination(
    audit_service: AuditService,
    audit_destination: AuditDestinationDTO,
) -> None:
    """Test deleting an audit destination."""
    assert audit_destination.id is not None, "Destination ID is None."

    await audit_service.delete_destination(audit_destination.id)

    destinations = await audit_service.get_destinations()
    assert all(dest.id != audit_destination.id for dest in destinations), (
        "Destination was not deleted successfully."
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_create_existing_audit_destination(
    audit_service: AuditService,
    audit_destination: AuditDestinationDTO,
) -> None:
    """Test creating an existing audit destination."""
    with pytest.raises(
        AuditAlreadyExistsError,
        match="Audit destination already exists",
    ):
        await audit_service.create_destination(audit_destination)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_update_non_existing_audit_destination(
    audit_service: AuditService,
    audit_destination: AuditDestinationDTO,
) -> None:
    """Test updating a non-existing audit destination."""
    assert audit_destination.id is not None, "Destination ID is None."
    with pytest.raises(
        AuditNotFoundError,
        match=f"Destination with id {audit_destination.id + 1} not found.",
    ):
        await audit_service.update_destination(
            audit_destination.id + 1,
            audit_destination,
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_delete_non_existing_audit_destination(
    audit_service: AuditService,
    audit_destination: AuditDestinationDTO,
) -> None:
    """Test deleting a non-existing audit destination."""
    assert audit_destination.id is not None, "Destination ID is None."
    with pytest.raises(
        AuditNotFoundError,
        match=f"Destination with id {audit_destination.id + 1} not found.",
    ):
        await audit_service.delete_destination(audit_destination.id + 1)
