"""
Access policy manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal, Optional, TypeVar

from sqlalchemy import ARRAY, String, bindparam, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.expression import Select, and_, or_

from app.api.main import schema as schemas
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.utils.const import ENTRY_TYPE
from ldap_protocol.utils.queries import (
    get_groups,
    get_path_filter,
    get_search_path,
)
from models import AccessPolicy, Directory, Group, GroupAccessPolicyMembership

T = TypeVar("T", bound=Select)
__all__ = [
    "get_access_policies",
    "get_access_policy",
    "create_access_policy",
    "mutate_ap",
    "delete_access_policy",
    "attach_access_policy_to_groups",
]


def compare_two_access_policies(
    ap_exist: AccessPolicy,
    ap_changed: schemas.AccessPolicyModifySchema,
) -> dict[str, Literal[True]]:
    """
    Calculate difference between two Access Policies.

    :param AccessPolicy ap_exist: existing Access Policy
    :param AccessPolicyModifySchema ap_changed: changed Access Policy

    :return dict[str, Literal[True]]: result
    """
    return {
        key: True
        for key in [
            "can_read",
            "can_add",
            "can_modify",
            "can_delete",
        ]
        if getattr(ap_exist, key) != getattr(ap_changed, key)
    }


async def get_access_policies(session: AsyncSession) -> list[AccessPolicy]:
    """Get all access policies.

    :param AsyncSession session: db

    :return list[AccessPolicy]: result
    """
    query = select(AccessPolicy).options(
        selectinload(AccessPolicy.groups).selectinload(Group.directory),
        selectinload(AccessPolicy.directories),
    )

    return list((await session.scalars(query)).all())


async def get_access_policy(name: str, session: AsyncSession) -> AccessPolicy:  # noqa A003
    """Get single Access Policy.

    :param id int: Access Policy's id
    :param AsyncSession session: db

    :return AccessPolicy: result
    """
    query = select(AccessPolicy).where(AccessPolicy.name == name).options(
        selectinload(AccessPolicy.groups).selectinload(Group.directory),
        selectinload(AccessPolicy.directories),
    )
    result = await session.scalars(query)
    return result.one()


async def create_access_policy(
    name: str,
    can_read: bool,
    can_add: bool,
    can_modify: bool,
    can_delete: bool,
    groups: list[ENTRY_TYPE],
    session: AsyncSession,
    grant_dn: Optional[ENTRY_TYPE] = None,
) -> AccessPolicy:
    """
    Create Access Policy.

    :param str name: name
    :param bool can_read: read permission
    :param bool can_add: add permission
    :param bool can_modify: modify permission
    :param bool can_delete: delete permission
    :param list[ENTRY_TYPE] groups: groups
    :param AsyncSession session: db
    :param Optional[ENTRY_TYPE] grant_dn: grant_dn

    :return AccessPolicy: result
    """
    if grant_dn:
        path = get_search_path(grant_dn)
        dir_filter = get_path_filter(
            column=Directory.path[1:len(path)],
            path=path,
        )

        directories = await session.scalars(
            select(Directory).where(dir_filter),
        )
        directories_ = directories.all()  # TODO FIXME сделай тут

    groups_dirs = await get_groups(groups, session)

    access_policy = AccessPolicy(
        name=name,
        can_read=can_read,
        can_add=can_add,
        can_modify=can_modify,
        can_delete=can_delete,
        directories=directories_,
        groups=groups_dirs,
    )
    session.add(access_policy)
    await session.flush()
    return access_policy


def mutate_ap(
    query: T,
    user: UserSchema,
    action: Literal["add", "read", "modify", "del"] = "read",
) -> T:
    """
    Modify query with read rule filter, joins acess policies.

    :param T query: select(Directory)
    :param UserSchema user: user data
    :param Literal["add", "read", "modify", "del"] action: action

    :return T: select(Directory).join(Directory.access_policies)
    """
    whitelist = AccessPolicy.id.in_(user.access_policies_ids)

    if action == "read":
        user_path = get_search_path(user.dn)
        get_upper_tree_elem = text(  # noqa: F811
            "(:path)[1:\"Directory\".\"depth\"]",
        ).bindparams(bindparam("path", value=user_path, type_=ARRAY(String)))

        ap_filter = or_(
            and_(AccessPolicy.can_read.is_(True), whitelist),
            Directory.id == user.directory_id,
            Directory.path == get_upper_tree_elem,
        )

    elif action == "add":
        ap_filter = AccessPolicy.can_add.is_(True) & whitelist

    elif action == "modify":
        ap_filter = AccessPolicy.can_modify.is_(True) & whitelist

    elif action == "del":
        ap_filter = AccessPolicy.can_delete.is_(True) & whitelist

    return query.join(Directory.access_policies, isouter=True).where(ap_filter)


async def delete_access_policy(
    access_policy_id: int,
    session: AsyncSession,
) -> None: # noqa A003
    """
    Delete Access Policy.

    :param int access_policy_id: Access Policy's id
    :param AsyncSession session: db

    :return None: None
    """
    access_policy = await session.get(AccessPolicy, access_policy_id)
    await session.delete(access_policy)
    await session.commit()


async def attach_access_policy_to_groups(
    access_policy_id: int,
    group_ids: list[int],
    session: AsyncSession,
) -> None:
    """
    Attach Access Policy to Group.

    :param int access_policy_id: Access Policy's id
    :param int group_ids: Group's id
    :param AsyncSession session: db

    :return None: None
    """
    for group_id in group_ids:
        session.add(
            GroupAccessPolicyMembership(
                policy_id=access_policy_id,
                group_id=group_id,
            ),
        )
    await session.commit()
