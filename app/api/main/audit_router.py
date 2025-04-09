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

from .schema import AuditPolicyRequest, AuditPolicySchema

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
            is_ldap=model.is_ldap,
            is_http=model.is_http,
            operation_code=model.operation_code,
            operation_success=model.operation_success,
            condition_attributes=model.condition_attributes,
            change_attributes=model.change_attributes,
        )
        for model in await session.scalars(select(AuditPolicy))
    ]


@audit_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user)],
)
@inject
async def add_audit_policy(
    policy: AuditPolicyRequest,
    session: FromDishka[AsyncSession],
) -> AuditPolicySchema:
    """Add policy.
    \f
    :param AuditPolicySchema policy: policy to add
    :raises HTTPException: 422 Entry already exists
    :return AuditPolicyResponse: Ready policy.
    """
    new_policy = AuditPolicy(
        id=policy.id,
        name=policy.name,
        is_ldap=policy.is_ldap,
        is_http=policy.is_http,
        operation_code=policy.operation_code,
        operation_success=policy.operation_success,
        condition_attributes=policy.condition_attributes,
        change_attributes=policy.change_attributes,
    )
    try:
        session.add(new_policy)
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Entry already exists",
        )

    return AuditPolicySchema(
        id=new_policy.id,
        name=new_policy.name,
        is_ldap=new_policy.is_ldap,
        is_http=new_policy.is_http,
        operation_code=new_policy.operation_code,
        operation_success=new_policy.operation_success,
        condition_attributes=new_policy.condition_attributes,
        change_attributes=new_policy.change_attributes,
    )


@audit_router.put("", dependencies=[Depends(get_current_user)])
@inject
async def update_network_policy(
    policy: AuditPolicySchema,
    session: FromDishka[AsyncSession],
) -> AuditPolicySchema:
    """Update network policy.
    \f
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
        for key, value in policy.model_dump(exclude_unset=True).items():
            setattr(selected_policy, key, value)

        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Entry already exists",
        )

    return policy


@audit_router.delete(
    "/{policy_id}",
    dependencies=[Depends(get_current_user)],
)
@inject
async def delete_audit_policy(
    policy_id: int,
    session: FromDishka[AsyncSession],
) -> None:
    """Delete policy."""
    policy = await session.get(AuditPolicy, policy_id, with_for_update=True)

    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")

    await session.delete(policy)
    await session.commit()
