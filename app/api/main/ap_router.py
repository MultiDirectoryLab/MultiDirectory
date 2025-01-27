"""Access policy management router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import FromDishka, inject
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from ldap_protocol.policies import access_policy as ap_api

from . import schema as schemas

access_policy_router = APIRouter(
    prefix="/access_policy", tags=["Access Policy"],
)


@access_policy_router.post("", status_code=status.HTTP_201_CREATED)
@inject
async def create_access_policy_(
    policy_data: schemas.AccessPolicyCreateSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new Access Policy.

    :param AccessPolicyCreateSchema policy_data: Data for creating
    a new access policy
    :param FromDishka[AsyncSession] session: db session
    """
    await ap_api.create_access_policy(
        name=policy_data.name,
        can_read=policy_data.can_read,
        can_add=policy_data.can_add,
        can_modify=policy_data.can_modify,
        can_delete=policy_data.can_delete,
        grant_dn=policy_data.grant_dn,
        groups=policy_data.groups,
        session=session,
    )


@access_policy_router.post("", status_code=status.HTTP_201_CREATED)
@inject
async def clone_access_policy_(
    access_policy_id: int,
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new Access Policy by exists Access Policy."""
    donor_access_policy = await ap_api.get_access_policy(
        access_policy_id,
        session,
    )

    if not donor_access_policy:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access policies not found",
        )

    await ap_api.create_access_policy(
        name=donor_access_policy.name,
        can_read=donor_access_policy.can_read,
        can_add=donor_access_policy.can_add,
        can_modify=donor_access_policy.can_modify,
        can_delete=donor_access_policy.can_delete,
        grant_dn="donor_access_policy.grant_dn",  # TODO FIXME
        groups=[g.directory.path_dn for g in donor_access_policy.groups],  # TODO FIXME
        session=session,
    )


@access_policy_router.get(
    "/{id}",
    response_model=schemas.MaterialAccessPolicySchema,
)
@inject
async def get_access_policy_(
    id: int,  # noqa A003
    session: FromDishka[AsyncSession],
) -> schemas.MaterialAccessPolicySchema:
    """Get a single Access Policy by ID.

    :param int id: Access Policy's id
    :param FromDishka[AsyncSession] session: db session

    :return MaterialAccessPolicySchema: Access Policy data
    """
    access_policy = await ap_api.get_access_policy(id, session)

    return schemas.MaterialAccessPolicySchema(
        id=access_policy.id,
        name=access_policy.name,
        can_read=access_policy.can_read,
        can_add=access_policy.can_add,
        can_modify=access_policy.can_modify,
        directories=[d.path_dn for d in access_policy.directories],
        groups=[g.directory.path_dn for g in access_policy.groups],
    )


@access_policy_router.get(
    "",
    response_model=list[schemas.MaterialAccessPolicySchema],
    dependencies=[Depends(get_current_user)],
)
@inject
async def get_access_policies_(
    session: FromDishka[AsyncSession],
) -> list[schemas.MaterialAccessPolicySchema]:
    """Get all Access Policies.

    :param FromDishka[AsyncSession] session: db session

    :return list[MaterialAccessPolicySchema]: List of Access Policies data
    """
    policies = await ap_api.get_access_policies(session)
    return [
        schemas.MaterialAccessPolicySchema(
            id=policy.id,
            name=policy.name,
            can_read=policy.can_read,
            can_add=policy.can_add,
            can_modify=policy.can_modify,
            directories=[d.path_dn for d in policy.directories],
            groups=[g.directory.path_dn for g in policy.groups],
        )
        for policy in policies
    ]


@access_policy_router.patch("/{access_policy_id}")
@inject
async def modify_access_policy_(
    access_policy_id: int,
    session: FromDishka[AsyncSession],
) -> None:
    """_summary_."""


@access_policy_router.delete("/{access_policy_id}")
@inject
async def delete_access_policy_(
    access_policy_id: int,
    session: FromDishka[AsyncSession],
) -> None:
    """Delete Access Policy by id.

    :param int access_policy_id: ID of the Access Policy to delete
    :param FromDishka[AsyncSession] session: db session
    """
    await ap_api.delete_access_policy(access_policy_id, session)


@access_policy_router.delete("/bulk")
@inject
async def delete_access_policies_(
    access_policies_data: list[schemas.AccessPolicyDeleteSchema],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete Access Policies by ids.

    :param list[AccessPolicyDeleteSchema] access_policies_data: List of
    Access Policies to delete
    :param FromDishka[AsyncSession] session: db session
    """
    if not access_policies_data:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access Policies not found",
        )

    for access_policy in access_policies_data:
        await ap_api.delete_access_policy(access_policy.id, session)
