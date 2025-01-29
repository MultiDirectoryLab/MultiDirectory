"""
Access Policy management router.

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


@access_policy_router.post(
    "",
    dependencies=[Depends(get_current_user)],
    response_model=schemas.MaterialAccessPolicySchema,
    status_code=status.HTTP_201_CREATED,
)
@inject
async def create_access_policy_(
    access_policy_data: schemas.MaterialAccessPolicySchema,
    grant_dn: str,
    session: FromDishka[AsyncSession],
) -> schemas.MaterialAccessPolicySchema:
    """
    Create a new Access Policy.

    :param AccessPolicyCreateSchema policy_data: Data for creating
    a new access policy
    :param str grant_dn: TODO FIXME 4enyxa
    :param FromDishka[AsyncSession] session: db session

    :return MaterialAccessPolicySchema: Created Access Policy data
    """
    access_policy = await ap_api.create_access_policy(
        name=access_policy_data.name,
        can_read=access_policy_data.can_read,
        can_add=access_policy_data.can_add,
        can_modify=access_policy_data.can_modify,
        can_delete=access_policy_data.can_delete,
        grant_dn=grant_dn,
        groups=access_policy_data.groups,
        session=session,
    )
    await session.commit()
    return schemas.MaterialAccessPolicySchema(
        id=access_policy.id,
        name=access_policy.name,
        can_read=access_policy.can_read,
        can_add=access_policy.can_add,
        can_modify=access_policy.can_modify,
        can_delete=access_policy.can_delete,
        directories=[d.path_dn for d in access_policy.directories],
        groups=[g.directory.path_dn for g in access_policy.groups],
    )


@access_policy_router.post(
    "",
    dependencies=[Depends(get_current_user)],
    response_model=schemas.MaterialAccessPolicySchema,
    status_code=status.HTTP_201_CREATED,
)
@inject
async def clone_access_policy_(
    access_policy_id: int,
    grant_dn: str,
    session: FromDishka[AsyncSession],
) -> schemas.MaterialAccessPolicySchema:
    """
    Create a new Access Policy by exists Access Policy.

    :param int access_policy_id: ID of the Access Policy to clone
    :param str grant_dn: TODO FIXME 4enyxa
    :param FromDishka[AsyncSession] session: db session

    :return MaterialAccessPolicySchema: Created Access Policy data
    """
    donor_access_policy = await ap_api.get_access_policy(
        access_policy_id,
        session,
    )

    if not donor_access_policy:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access Policy not found",
        )

    access_policy = await ap_api.create_access_policy(
        name=donor_access_policy.name,
        can_read=donor_access_policy.can_read,
        can_add=donor_access_policy.can_add,
        can_modify=donor_access_policy.can_modify,
        can_delete=donor_access_policy.can_delete,
        grant_dn=grant_dn,  # TODO FIXME
        groups=[g.directory.path_dn for g in donor_access_policy.groups],  # TODO FIXME
        session=session,
    )

    return schemas.MaterialAccessPolicySchema(
        id=access_policy.id,
        name=access_policy.name,
        can_read=access_policy.can_read,
        can_add=access_policy.can_add,
        can_modify=access_policy.can_modify,
        can_delete=access_policy.can_delete,
        directories=[d.path_dn for d in access_policy.directories],
        groups=[g.directory.path_dn for g in access_policy.groups],
    )


@access_policy_router.get(
    "/{access_policy_id}",
    dependencies=[Depends(get_current_user)],
    response_model=schemas.MaterialAccessPolicySchema,
    status_code=status.HTTP_200_OK,
)
@inject
async def get_access_policy_(
    access_policy_id: int,  # noqa A003
    session: FromDishka[AsyncSession],
) -> schemas.MaterialAccessPolicySchema:
    """
    Get a single Access Policy by ID.

    :param int access_policy_id: ID of the Access Policy to get
    :param FromDishka[AsyncSession] session: db session

    :return MaterialAccessPolicySchema: Access Policy data
    """
    access_policy = await ap_api.get_access_policy(access_policy_id, session)

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
    dependencies=[Depends(get_current_user)],
    response_model=list[schemas.MaterialAccessPolicySchema],
    status_code=status.HTTP_200_OK,
)
@inject
async def get_access_policies_(
    session: FromDishka[AsyncSession],
) -> list[schemas.MaterialAccessPolicySchema]:
    """Get all Access Policies.

    :param FromDishka[AsyncSession] session: db session

    :return list[MaterialAccessPolicySchema]: List of Access Policies data
    """
    access_policies = await ap_api.get_access_policies(session)
    return [
        schemas.MaterialAccessPolicySchema(
            id=access_policy.id,
            name=access_policy.name,
            can_read=access_policy.can_read,
            can_add=access_policy.can_add,
            can_modify=access_policy.can_modify,
            directories=(d.path_dn for d in access_policy.directories),
            groups=(g.directory.path_dn for g in access_policy.groups),
        )
        for access_policy in access_policies
    ]


@access_policy_router.patch(
    "/{access_policy_id}",
    dependencies=[Depends(get_current_user)],
    response_model=schemas.MaterialAccessPolicySchema,
    status_code=status.HTTP_200_OK,
)
@inject
async def modify_access_policy_(
    access_policy_id: int,
    access_policy_changed: schemas.AccessPolicyModifySchema,
    session: FromDishka[AsyncSession],
) -> schemas.MaterialAccessPolicySchema:
    """
    Modify Access Policy.

    :param int access_policy_id: ID of the Access Policy to modify
    :param AccessPolicyModifySchema access_policy_changed: Data for modifying
    :param FromDishka[AsyncSession] session: db session

    :return MaterialAccessPolicySchema: Created Access Policy data
    """
    access_policy = await ap_api.get_access_policy(
        access_policy_id,
        session,
    )

    if not access_policy:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access Policy not found",
        )

    access_policy.name = access_policy_changed.name
    access_policy.can_read = access_policy_changed.can_read
    access_policy.can_add = access_policy_changed.can_add
    access_policy.can_modify = access_policy_changed.can_modify
    access_policy.can_delete = access_policy_changed.can_delete
    access_policy.directories = [
        d.path_dn for d in access_policy_changed.directories
    ]
    access_policy.groups = [
        g.directory.path_dn for g in access_policy_changed.groups  # TODO FIXME
    ]

    return schemas.MaterialAccessPolicySchema(
        id=access_policy.id,
        name=access_policy.name,
        can_read=access_policy.can_read,
        can_add=access_policy.can_add,
        can_modify=access_policy.can_modify,
        can_delete=access_policy.can_delete,
        directories=[d.path_dn for d in access_policy.directories],
        groups=[g.directory.path_dn for g in access_policy.groups],
    )


@access_policy_router.delete(
    "/{access_policy_id}",
    dependencies=[Depends(get_current_user)],
    status_code=status.HTTP_204_NO_CONTENT,
)
@inject
async def delete_access_policy_(
    access_policy_id: int,
    session: FromDishka[AsyncSession],
) -> None:
    """
    Delete Access Policy by id.

    :param int access_policy_id: ID of the Access Policy to delete
    :param FromDishka[AsyncSession] session: db session

    :return None
    """
    await ap_api.delete_access_policy(access_policy_id, session)


@access_policy_router.delete(
    "/bulk",
    dependencies=[Depends(get_current_user)],
    status_code=status.HTTP_204_NO_CONTENT,
)
@inject
async def delete_access_policies_(
    access_policies_data: list[schemas.AccessPolicyDeleteSchema],
    session: FromDishka[AsyncSession],
) -> None:
    """
    Delete Access Policies by ids.

    :param list[AccessPolicyDeleteSchema] access_policies_data: List of
    Access Policies to delete
    :param FromDishka[AsyncSession] session: db session

    :return None
    """
    if not access_policies_data:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access Policies not found",
        )

    for access_policy in access_policies_data:
        await ap_api.delete_access_policy(access_policy.id, session)


@access_policy_router.post(
    "/attach",
    dependencies=[Depends(get_current_user)],
    status_code=status.HTTP_201_CREATED,
)
@inject
async def attach_access_policy_to_group_(
    access_policy_id: int,
    group_id: int,
    session: FromDishka[AsyncSession],
) -> None:
    """
    Attach Access Policy to Group.

    :param int access_policy_id: ID of the Access Policy to attach
    :param FromDishka[AsyncSession] session: db session

    :return None
    """
    await ap_api.attach_access_policy_to_group(
        access_policy_id,
        group_id,
        session,
    )
