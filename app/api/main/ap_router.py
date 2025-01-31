"""
Access Policy management router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


from dishka.integrations.fastapi import FromDishka, inject
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from ldap_protocol.policies.access_policy import (
    attach_access_policy_to_groups,
    compare_two_access_policies,
    create_access_policy,
    delete_access_policy,
    get_access_policies,
    get_access_policy,
)

from .schema import (
    AccessPolicyModifySchema,
    AccessPolicySchema,
    MaterialAccessPolicySchema,
)

access_policy_router = APIRouter(
    prefix="/access_policy",
    dependencies=[Depends(get_current_user)],
    tags=["Access Policy"],
)


@access_policy_router.post(
    "",
    response_model=AccessPolicySchema,
    status_code=status.HTTP_201_CREATED,
)
@inject
async def create_access_policy_(
    access_policy_data: AccessPolicySchema,
    session: FromDishka[AsyncSession],
) -> AccessPolicySchema:
    """
    Create a new Access Policy.

    :param AccessPolicyCreateSchema policy_data: Data for creating
    a new access policy
    :param FromDishka[AsyncSession] session: db session

    :return AccessPolicySchema: Created Access Policy data
    """
    access_policy = await create_access_policy(
        name=access_policy_data.name,
        can_read=access_policy_data.can_read,
        can_add=access_policy_data.can_add,
        can_modify=access_policy_data.can_modify,
        can_delete=access_policy_data.can_delete,
        groups=access_policy_data.groups,
        session=session,
    )
    await session.commit()
    return AccessPolicySchema(
        name=access_policy.name,
        can_read=access_policy.can_read,
        can_add=access_policy.can_add,
        can_modify=access_policy.can_modify,
        can_delete=access_policy.can_delete,
        # directories=[d.path_dn for d in access_policy.directories],
        groups=[g.directory.path_dn for g in access_policy.groups],
    )


@access_policy_router.post(
    "/clone",
    response_model=MaterialAccessPolicySchema,
    status_code=status.HTTP_201_CREATED,
)
@inject
async def clone_access_policy_(
    donor_access_policy_name: str,
    access_policy_name: str,
    session: FromDishka[AsyncSession],
) -> MaterialAccessPolicySchema:
    """
    Create a new Access Policy by exists Access Policy. New Access Policy name
    must be unique.

    :param str access_policy_name: Name of the Access Policy to clone
    :param FromDishka[AsyncSession] session: db session

    :return MaterialAccessPolicySchema: Created Access Policy data
    """
    if donor_access_policy_name == access_policy_name:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Access Policy names must be unique",
        )

    donor_access_policy = await get_access_policy(
        donor_access_policy_name,
        session,
    )
    if not donor_access_policy:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Donor Access Policy not found",
        )

    access_policy = await create_access_policy(
        name=access_policy_name,
        can_read=donor_access_policy.can_read,
        can_add=donor_access_policy.can_add,
        can_modify=donor_access_policy.can_modify,
        can_delete=donor_access_policy.can_delete,
        groups=[g.directory.path_dn for g in donor_access_policy.groups],  # TODO FIXME
        session=session,
    )

    return MaterialAccessPolicySchema(
        name=access_policy.name,
        can_read=access_policy.can_read,
        can_add=access_policy.can_add,
        can_modify=access_policy.can_modify,
        can_delete=access_policy.can_delete,
        directories=[d.path_dn for d in access_policy.directories],
        groups=[g.directory.path_dn for g in access_policy.groups],
    )


@access_policy_router.get(
    "/{access_policy_name}",
    response_model=MaterialAccessPolicySchema,
    status_code=status.HTTP_200_OK,
)
@inject
async def get_access_policy_(
    access_policy_name: str,
    session: FromDishka[AsyncSession],
) -> MaterialAccessPolicySchema:
    """
    Get a single Access Policy by name.

    :param str access_policy_name: Name of the Access Policy to get
    :param FromDishka[AsyncSession] session: db session

    :return MaterialAccessPolicySchema: Access Policy data
    """
    access_policy = await get_access_policy(access_policy_name, session)
    if not access_policy:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access Policy not found",
        )

    return MaterialAccessPolicySchema(
        name=access_policy.name,
        can_read=access_policy.can_read,
        can_add=access_policy.can_add,
        can_modify=access_policy.can_modify,
        can_delete=access_policy.can_delete,
        directories=[d.path_dn for d in access_policy.directories],
        groups=[g.directory.path_dn for g in access_policy.groups],
    )


@access_policy_router.get(
    "",
    response_model=list[MaterialAccessPolicySchema],
    status_code=status.HTTP_200_OK,
)
@inject
async def get_access_policies_(
    session: FromDishka[AsyncSession],
) -> list[MaterialAccessPolicySchema]:
    """Get all Access Policies.

    :param FromDishka[AsyncSession] session: db session

    :return list[MaterialAccessPolicySchema]: List of Access Policies data
    """
    access_policies = await get_access_policies(session)
    return [
        MaterialAccessPolicySchema(
            name=access_policy.name,
            can_read=access_policy.can_read,
            can_add=access_policy.can_add,
            can_modify=access_policy.can_modify,
            can_delete=access_policy.can_delete,
            directories=(d.path_dn for d in access_policy.directories),
            groups=(g.directory.path_dn for g in access_policy.groups),
        )
        for access_policy in access_policies
    ]


@access_policy_router.patch(
    "/{access_policy_name}",
    response_model=MaterialAccessPolicySchema,
    status_code=status.HTTP_200_OK,
)
@inject
async def modify_access_policy_(
    access_policy_name: str,
    access_policy_changes: AccessPolicyModifySchema,
    session: FromDishka[AsyncSession],
) -> MaterialAccessPolicySchema:
    """
    Modify Access Policy.

    :param str access_policy_name: Name of the Access Policy to modify
    :param AccessPolicyModifySchema access_policy_changes: Data for modifying
    :param FromDishka[AsyncSession] session: db session

    :return MaterialAccessPolicySchema: Created Access Policy data
    """
    access_policy = await get_access_policy(
        access_policy_name,
        session,
    )
    if not access_policy:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access Policy not found",
        )

    if not compare_two_access_policies(
        access_policy,
        access_policy_changes,
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "",
        )

    access_policy.can_read = access_policy_changes.can_read
    access_policy.can_add = access_policy_changes.can_add
    access_policy.can_modify = access_policy_changes.can_modify
    access_policy.can_delete = access_policy_changes.can_delete

    return MaterialAccessPolicySchema(
        name=access_policy.name,
        can_read=access_policy.can_read,
        can_add=access_policy.can_add,
        can_modify=access_policy.can_modify,
        can_delete=access_policy.can_delete,
        directories=[d.path_dn for d in access_policy.directories],
        groups=[g.directory.path_dn for g in access_policy.groups],
    )


@access_policy_router.delete(
    "/bulk",
    status_code=status.HTTP_204_NO_CONTENT,
)
@inject
async def delete_access_policies_(
    access_policy_names: list[int],
    session: FromDishka[AsyncSession],
) -> None:
    """
    Delete Access Policies by names.

    :param list[int] access_policy_names: List of Access Policies names
    :param FromDishka[AsyncSession] session: db session

    :return None
    """
    if not access_policy_names:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access Policies not found",
        )

    for access_policy_name in access_policy_names:
        await delete_access_policy(access_policy_name, session)


@access_policy_router.post(
    "/attach",
    status_code=status.HTTP_201_CREATED,
)
@inject
async def attach_access_policy_to_group_(
    access_policy_name: str,
    group_ids: list[str],  # TODO FIXME у групп нет айдишников
    session: FromDishka[AsyncSession],
) -> None:
    """
    Attach Access Policy to Group.

    :param str access_policy_name: Name of the Access Policy
    :param list[str] group_ids: Search string for group
    :param FromDishka[AsyncSession] session: db session

    :return None
    """
    if not group_ids:  # TODO FIXME у групп нет айдишников
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Groups not found",
        )

    access_policy = await get_access_policy(access_policy_name, session)
    if not access_policy:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access Policy not found",
        )

    # TODO FIXME group_ids = [список из str]
    await attach_access_policy_to_groups(
        access_policy_id=access_policy.id,
        group_ids=group_ids,  # TODO FIXME у групп нет айдишников
        session=session,
    )
