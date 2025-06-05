"""Audit policies.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Depends, HTTPException, status
from fastapi.routing import APIRouter
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from models import AuditDestination, AuditPolicy

from .schema import (
    AuditDestinationSchema,
    AuditDestinationSchemaRequest,
    AuditPolicySchema,
)

audit_router = APIRouter(
    prefix="/audit",
    tags=["Audit policy"],
    dependencies=[Depends(get_current_user)],
)


@audit_router.get("/policies", status_code=status.HTTP_201_CREATED)
@inject
async def get_audit_policies(
    session: FromDishka[AsyncSession],
) -> list[AuditPolicySchema]:
    """Get policies."""
    return [
        AuditPolicySchema(
            id=model.id,
            name=model.name,
            is_enabled=model.is_enabled,
        )
        for model in await session.scalars(select(AuditPolicy))
    ]


@audit_router.put("/policy")
@inject
async def update_network_policy(
    policy: AuditPolicySchema,
    session: FromDishka[AsyncSession],
) -> AuditPolicySchema:
    """Update network policy.

    :param AuditPolicySchema policy: update request
    :raises HTTPException: 404 policy not found
    :raises HTTPException: 422 Entry already exists
    :return AuditPolicySchema: Policy from database.
    """
    selected_policy = await session.get(
        AuditPolicy,
        policy.id,
        with_for_update=True,
    )

    if not selected_policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    try:
        selected_policy.id = policy.id
        selected_policy.name = policy.name
        selected_policy.is_enabled = policy.is_enabled

        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Entry already exists",
        )

    return policy


@audit_router.get("/destinations")
@inject
async def get_audit_destinations(
    session: FromDishka[AsyncSession],
) -> list[AuditDestinationSchema]:
    """Get audit destinations.

    :return list[AuditDestinationSchema]: List of destinations.
    """
    return [
        AuditDestinationSchema.model_validate(model)
        for model in await session.scalars(select(AuditDestination))
    ]


@audit_router.post("/destination", status_code=status.HTTP_201_CREATED)
@inject
async def add_audit_destination(
    model: AuditDestinationSchemaRequest,
    session: FromDishka[AsyncSession],
) -> AuditDestinationSchema:
    """Add audit destination."""
    try:
        new_destination = AuditDestination(
            name=model.name,
            service_type=model.service_type,
            is_enabled=model.is_enabled,
            host=model.host,
            port=model.port,
            username=model.username,
            password=model.password,
            protocol=model.protocol,
            tls_verify_cert=model.tls_verify_cert,
            ca_cert_data=model.ca_cert_data,
            client_cert_data=model.client_cert_data,
            client_key_data=model.client_key_data,
        )
        session.add(new_destination)
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Entry already exists",
        )

    return AuditDestinationSchema.model_validate(new_destination)


@audit_router.put("/destination")
@inject
async def update_audit_destination(
    model: AuditDestinationSchema,
    session: FromDishka[AsyncSession],
) -> AuditDestinationSchema:
    """Update audit destination."""
    selected_destination = await session.get(
        AuditDestination,
        model.id,
        with_for_update=True,
    )

    if not selected_destination:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Destination not found")

    try:
        selected_destination.name = model.name
        selected_destination.service_type = model.service_type
        selected_destination.is_enabled = model.is_enabled
        selected_destination.host = model.host
        selected_destination.port = model.port
        selected_destination.username = model.username
        selected_destination.password = model.password
        selected_destination.protocol = model.protocol
        selected_destination.tls_verify_cert = model.tls_verify_cert
        selected_destination.ca_cert_data = model.ca_cert_data
        selected_destination.client_cert_data = model.client_cert_data
        selected_destination.client_key_data = model.client_key_data

        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Entry already exists",
        )

    return model


@audit_router.delete("/destination/{destination_id}")
@inject
async def delete_audit_destination(
    destination_id: int,
    session: FromDishka[AsyncSession],
) -> None:
    """Update network policy.

    :param AuditPolicySchema policy: update request
    :raises HTTPException: 404 policy not found
    :raises HTTPException: 422 Entry already exists
    :return AuditPolicySchema: Policy from database.
    """
    selected_destination = await session.get(
        AuditDestination,
        destination_id,
    )

    if not selected_destination:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Destination not found")

    await session.delete(selected_destination)
    await session.commit()
