"""Access policy management router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import FromDishka, inject
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.expression import any_

from api.auth import get_current_user
from ldap_protocol.utils import get_groups, get_path_filter, get_search_path
from models import AccessPolicy, Directory

from .schema import AccessPolicySchema, MaterialAccessPolicySchema

access_policy_router = APIRouter(prefix='access_policy')


@access_policy_router.get('/', dependencies=[Depends(get_current_user)])
@inject
async def get_access_policies(
    session: FromDishka[AsyncSession],
) -> list[MaterialAccessPolicySchema]:
    """Get APs.
    \f
    :param AccessPolicySchema policy: ap
    :param FromDishka[AsyncSession] session: db
    """
    return [
        MaterialAccessPolicySchema.model_validate(policy, from_attributes=True)
        for policy in await session.scalars(select(AccessPolicy))
    ]


@access_policy_router.post('/', dependencies=[Depends(get_current_user)])
@inject
async def create_access_policy(
    policy: AccessPolicySchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Get APs.
    \f
    :param AccessPolicySchema policy: ap
    :param FromDishka[AsyncSession] session: db
    """
    dir_filter = any_(get_path_filter(get_search_path()))
    directories = await session.scalars(
        select(Directory).join(Directory.path).where(dir_filter))

    session.add(AccessPolicy(
        name=policy.name,
        can_read=policy.can_read,
        can_add=policy.can_add,
        can_modify=policy.can_modify,
        groups=await get_groups(policy.groups, session),
        directories=directories,
    ))
    await session.commit()
