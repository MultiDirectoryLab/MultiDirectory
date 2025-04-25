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
from models import AuditPolicy

from .schema import AuditPolicySchema

audit_router = APIRouter(prefix="/audit", tags=["Audit policy"])


@audit_router.get(
    "",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user)],
)
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


@audit_router.put("", dependencies=[Depends(get_current_user)])
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
