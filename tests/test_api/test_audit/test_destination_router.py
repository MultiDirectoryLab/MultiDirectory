"""Test audit destination API.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
import pytest_asyncio
from fastapi import status
from httpx import AsyncClient

from ldap_protocol.policies.audit.enums import (
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
)
from ldap_protocol.policies.audit.schemas import (
    AuditDestinationSchema,
    AuditDestinationSchemaRequest,
)


def assert_correct_destination(
    destination: AuditDestinationSchema,
    model: AuditDestinationSchemaRequest,
) -> None:
    """Assert that the audit destination matches the request model."""
    assert destination.name == model.name
    assert destination.service_type == model.service_type
    assert destination.protocol == model.protocol
    assert destination.host == model.host
    assert destination.port == model.port
    assert destination.is_enabled == model.is_enabled


async def get_and_check_destination(
    http_client: AsyncClient,
    model: AuditDestinationSchemaRequest,
) -> AuditDestinationSchema:
    """Get and check the audit destination."""
    response = await http_client.get("/audit/destinations")
    assert response.status_code == status.HTTP_200_OK
    destinations = response.json()
    created_destination = next(
        (
            AuditDestinationSchema(**d)
            for d in destinations
            if d["name"] == model.name
        ),
        None,
    )
    assert created_destination is not None, "Destination should not be None"
    assert_correct_destination(created_destination, model)

    return created_destination


@pytest_asyncio.fixture(scope="function")
async def audit_destination(
    http_client: AsyncClient,
) -> AuditDestinationSchema:
    """Fixture to create an audit destination."""
    model = AuditDestinationSchemaRequest(
        name="Test Destination",
        service_type=AuditDestinationServiceType.SYSLOG,
        protocol=AuditDestinationProtocolType.TCP,
        host="localhost",
        port=514,
        is_enabled=True,
    )

    response = await http_client.post(
        "/audit/destination",
        json=model.model_dump(),
    )

    assert response.status_code == status.HTTP_201_CREATED

    return await get_and_check_destination(
        http_client=http_client,
        model=model,
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_update_audit_destination(
    http_client: AsyncClient,
    audit_destination: AuditDestinationSchema,
) -> None:
    """Test create an audit destination."""
    model = AuditDestinationSchemaRequest(
        name="Test Destination",
        service_type=AuditDestinationServiceType.SYSLOG,
        protocol=AuditDestinationProtocolType.UDP,
        host="syslog.example.com    ",
        port=555,
        is_enabled=False,
    )

    response = await http_client.put(
        f"/audit/destination/{audit_destination.id}",
        json=model.model_dump(),
    )

    assert response.status_code == status.HTTP_200_OK

    await get_and_check_destination(
        http_client=http_client,
        model=model,
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_audit_destination(
    http_client: AsyncClient,
    audit_destination: AuditDestinationSchema,
) -> None:
    """Test delete an audit destination."""
    response = await http_client.delete(
        f"/audit/destination/{audit_destination.id}",
    )

    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get("/audit/destinations")
    assert response.status_code == status.HTTP_200_OK
    destinations = response.json()
    assert not any(d["id"] == audit_destination.id for d in destinations), (
        "Destination should be deleted"
    )
