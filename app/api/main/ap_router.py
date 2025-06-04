"""Access policy management router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import FromDishka, inject
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from ldap_protocol.policies.access_policy import get_policies

from .schema import MaterialAccessPolicySchema

access_policy_router = APIRouter(
    prefix="/access_policy",
    tags=["Access Policy"],
)


@access_policy_router.get("", dependencies=[Depends(get_current_user)])
@inject
async def get_access_policies(
    session: FromDishka[AsyncSession],
) -> list[MaterialAccessPolicySchema]:
    """Get APs.

    \f
    Args:
        session (FromDishka[AsyncSession]): db.

    Returns:
        list[MaterialAccessPolicySchema]: list of access policies.
    """
    return [
        MaterialAccessPolicySchema(
            id=policy.id,
            name=policy.name,
            can_read=policy.can_read,
            can_add=policy.can_add,
            can_modify=policy.can_modify,
            directories=(d.path_dn for d in policy.directories),
            groups=(g.directory.path_dn for g in policy.groups),
        )
        for policy in await get_policies(session)
    ]
