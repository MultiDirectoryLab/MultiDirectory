"""Test audit destination API.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest
from fastapi import status
from httpx import AsyncClient

from ldap_protocol.policies.audit.dataclasses import AuditDestinationDTO
from ldap_protocol.policies.audit.enums import (
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
)
from ldap_protocol.policies.audit.schemas import AuditDestinationSchemaRequest


@pytest.mark.asyncio
async def test_create_audit_destination(
    http_client: AsyncClient,
    audit_service: Mock,
) -> None:
    """Test create an audit destination."""
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
    result_dto = audit_service.create_destination.call_args.args[0]
    assert result_dto == AuditDestinationDTO(**model.model_dump())


@pytest.mark.asyncio
async def test_update_audit_destination(
    http_client: AsyncClient,
    audit_service: Mock,
) -> None:
    """Test create an audit destination."""
    destination_id = 1
    model = AuditDestinationSchemaRequest(
        name="Test Destination",
        service_type=AuditDestinationServiceType.SYSLOG,
        protocol=AuditDestinationProtocolType.UDP,
        host="syslog.example.com    ",
        port=555,
        is_enabled=False,
    )

    response = await http_client.put(
        f"/audit/destination/{destination_id}",
        json=model.model_dump(),
    )

    assert response.status_code == status.HTTP_200_OK

    result_destionation_id, result_dto = (
        audit_service.update_destination.call_args.args
    )
    assert result_destionation_id == destination_id
    assert result_dto == AuditDestinationDTO(**model.model_dump())


@pytest.mark.asyncio
async def test_delete_audit_destination(
    http_client: AsyncClient,
    audit_service: Mock,
) -> None:
    """Test delete an audit destination."""
    destination_id = 1
    response = await http_client.delete(
        f"/audit/destination/{destination_id}",
    )

    assert response.status_code == status.HTTP_200_OK
    assert audit_service.delete_destination.call_args.args[0] == destination_id
