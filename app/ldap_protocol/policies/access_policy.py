"""Access policy manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal, TypeVar

from pydantic import BaseModel
from sqlalchemy import ARRAY, String, bindparam, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.expression import Select, and_, or_

from ldap_protocol.dialogue import UserSchema
from ldap_protocol.utils.const import ENTRY_TYPE
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    BaseSchemaModel,
    PaginationParams,
    PaginationResult,
)
from ldap_protocol.utils.queries import (
    get_groups,
    get_path_filter,
    get_search_path,
)
from models import AccessPolicy, Directory, Group

T = TypeVar("T", bound=Select)
__all__ = ["get_access_policy_paginator", "create_access_policy", "mutate_ap"]


class _PolicyFields:
    name: str
    can_read: bool
    can_add: bool
    can_modify: bool
    directories: list[str]
    groups: list[str]


class _MaterialFields:
    id: int


class AccessPolicySchema(_PolicyFields, BaseModel):
    """AP Schema w/o id."""


class MaterialAccessPolicySchema(
    _PolicyFields,
    _MaterialFields,
    BaseSchemaModel,
):
    """AP Schema with id."""

    @classmethod
    def from_db(
        cls,
        access_policy: AccessPolicy,
    ) -> "MaterialAccessPolicySchema":
        """Create an instance from database."""
        return cls(
            id=access_policy.id,
            name=access_policy.name,
            can_read=access_policy.can_read,
            can_add=access_policy.can_add,
            can_modify=access_policy.can_modify,
            directories=(d.path_dn for d in access_policy.directories),
            groups=(g.directory.path_dn for g in access_policy.groups),
        )


class AccessPolicyPaginationSchema(
    BasePaginationSchema[MaterialAccessPolicySchema]
):
    """Attribute Type Schema with pagination result."""

    items: list[MaterialAccessPolicySchema]


async def get_access_policy_paginator(
    params: PaginationParams,
    session: AsyncSession,
) -> PaginationResult:
    """Retrieve paginated AccessPolicies.

    :param PaginationParams params: page_size and page_number.
    :param AsyncSession session: Database session.
    :return PaginationResult: Chunk of AccessPolicies. and metadata.
    """
    query = (
        select(AccessPolicy)
        .options(
            selectinload(AccessPolicy.groups).selectinload(Group.directory),
            selectinload(AccessPolicy.directories),
        )
        .order_by(AccessPolicy.id)
    )

    return await PaginationResult[AccessPolicy].get(
        params=params,
        query=query,
        sqla_model=AccessPolicy,
        session=session,
    )


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
        column=Directory.path[1 : len(path)],
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
        get_upper_tree_elem = text(
            '(:path)[1:"Directory"."depth"]',
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
