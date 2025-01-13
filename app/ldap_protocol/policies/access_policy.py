"""Access policy manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal, TypeVar

from sqlalchemy import ARRAY, String, bindparam, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.expression import Select, and_, or_

from ldap_protocol.dialogue import UserSchema
from ldap_protocol.utils.const import ENTRY_TYPE
from ldap_protocol.utils.queries import (
    get_groups,
    get_path_filter,
    get_search_path,
)
from models import AccessPolicy, Directory, Group

T = TypeVar("T", bound=Select)
__all__ = ["get_policies", "create_access_policy", "mutate_ap"]


async def get_policies(session: AsyncSession) -> list[AccessPolicy]:
    """Get policies.

    :param AsyncSession session: db
    :return list[AccessPolicy]: result
    """
    query = select(AccessPolicy).options(
        selectinload(AccessPolicy.groups).selectinload(Group.directory),
        selectinload(AccessPolicy.directories),
    )

    return list((await session.scalars(query)).all())


async def create_access_policy(
    name: str,
    can_read: bool,
    can_add: bool,
    can_modify: bool,
    can_delete: bool,
    grant_dn: ENTRY_TYPE,
    groups: list[ENTRY_TYPE],
    session: AsyncSession,
) -> None:
    """Get policies.

    :param ENTRY_TYPE grant_dn: main dn
    :param AsyncSession session: session
    """
    path = get_search_path(grant_dn)
    dir_filter = get_path_filter(
        column=Directory.path[1:len(path)],
        path=path,
    )

    directories = await session.scalars(select(Directory).where(dir_filter))
    groups_dirs = await get_groups(groups, session)

    policy = AccessPolicy(
        name=name,
        can_read=can_read,
        can_add=can_add,
        can_modify=can_modify,
        can_delete=can_delete,
        directories=directories.all(),
        groups=groups_dirs,
    )
    session.add(policy)
    await session.flush()


def mutate_ap(
    query: T,
    user: UserSchema,
    action: Literal["add", "read", "modify", "del"] = "read",
) -> T:
    """Modify query with read rule filter, joins acess policies.

    :param T query: select(Directory)
    :param UserSchema user: user data
    :return T: select(Directory).join(Directory.access_policies)
    """
    whitelist = AccessPolicy.id.in_(user.access_policies_ids)

    if action == "read":
        user_path = get_search_path(user.dn)
        ap_filter = or_(
            and_(AccessPolicy.can_read.is_(True), whitelist),
            Directory.id == user.directory_id,
            Directory.path == text("(:user_path)[1:\"Directory\".\"depth\"]")
            .bindparams(
                bindparam("user_path", value=user_path, type_=ARRAY(String)),
            ),
        )

    elif action == "add":
        ap_filter = AccessPolicy.can_add.is_(True) & whitelist

    elif action == "modify":
        ap_filter = AccessPolicy.can_modify.is_(True) & whitelist

    elif action == "del":
        ap_filter = AccessPolicy.can_delete.is_(True) & whitelist

    return query.join(Directory.access_policies, isouter=True).where(ap_filter)
