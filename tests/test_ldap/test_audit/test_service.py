"""Test audit service.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
import pytest_asyncio

from enums import (
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
    ErrorCode,
)
from ldap_protocol.policies.audit.dataclasses import (
    AuditDestinationDTO,
    AuditPolicyDTO,
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

    name = "Test Policy"
    new_policy = AuditPolicyDTO(
        name=name,
        is_enabled=True,
        severity=old_policy.severity,
    )

    await audit_service.update_policy(old_policy.get_id(), new_policy)

    for policy in await audit_service.get_policies():
        if policy.name == name:
            assert policy == new_policy
            break
    else:
        pytest.fail(
            f"Policy with id {old_policy.get_id()} "
            "not found in updated policies.",
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_update_audit_policy_with_non_existing_id(
    audit_service: AuditService,
) -> None:
    """Test updating an audit policy."""
    latest_policy = (await audit_service.get_policies())[-1]

    possible_id = latest_policy.get_id() + 1

    new_policy = AuditPolicyDTO(
        name="Test Policy",
        is_enabled=True,
        severity=latest_policy.severity,
    )

    with pytest.raises(
        AuditNotFoundError,
        match=f"Policy with id {possible_id} not found.",
    ) as exc_info:
        await audit_service.update_policy(possible_id, new_policy)

    assert exc_info.value._code == ErrorCode.AUDIT_NOT_FOUND  # type: ignore # noqa: SLF001


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
    ) as exc_info:
        await audit_service.create_destination(audit_destination)

    assert exc_info.value._code == ErrorCode.AUDIT_ALREADY_EXISTS  # type: ignore # noqa: SLF001


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_service_update_non_existing_audit_destination(
    audit_service: AuditService,
    audit_destination: AuditDestinationDTO,
) -> None:
    """Test updating a non-existing audit destination."""
    assert audit_destination.id is not None, "Destination ID is None."
    provision_id = audit_destination.get_id() + 1
    with pytest.raises(
        AuditNotFoundError,
        match=f"Destination with id {provision_id} not found.",
    ) as exc_info:
        await audit_service.update_destination(
            provision_id,
            audit_destination,
        )

    assert exc_info.value._code == ErrorCode.AUDIT_NOT_FOUND  # type: ignore # noqa: SLF001


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
    ) as exc_info:
        await audit_service.delete_destination(audit_destination.id + 1)

    assert exc_info.value._code == ErrorCode.AUDIT_NOT_FOUND  # type: ignore # noqa: SLF001
