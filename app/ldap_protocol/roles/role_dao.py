"""Role DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from ldap_protocol.roles.enums import AceType, RoleScope
from ldap_protocol.utils.const import GRANT_DN_STRING
from ldap_protocol.utils.helpers import get_depth_by_dn
from ldap_protocol.utils.queries import (
    get_groups,
    get_path_filter,
    get_search_path,
)
from models import AccessControlEntry, Directory, Group, Role


class AccessControlEntrySchema(BaseModel):
    """Base schema Access Control Entry."""

    ace_type: AceType
    scope: RoleScope
    base_dn: GRANT_DN_STRING
    attribute_type_id: int | None = None
    entity_type_id: int | None = None
    is_allow: bool = True


class RoleBaseSchema(BaseModel):
    """Schema for a role."""

    name: str
    creator_upn: str | None
    is_system: bool
    groups_path_dn: list[str]


class RoleDAO:
    """Role DAO."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Role DAO with a database session."""
        self._session = session

    async def get_role(self, role_id: int) -> Role | None:
        """Get a role by its ID.

        :param role_id: ID of the role to retrieve.
        :return: Role object if found, None otherwise.
        """
        query = (
            select(Role)
            .options(
                selectinload(Role.groups),
                selectinload(Role.access_control_entries).options(
                    joinedload(AccessControlEntry.attribute_type),
                    joinedload(AccessControlEntry.entity_type),
                    joinedload(AccessControlEntry.role),
                ),
            )
            .where(Role.id == role_id)
        )
        result = await self._session.execute(query)
        return result.scalars().first()

    async def get_all_roles(self) -> list[Role]:
        """Get all roles.

        :return: List of Role objects.
        """
        return list(
            (
                await self._session.scalars(
                    select(Role).options(selectinload(Role.groups))
                )
            ).all()
        )

    async def create_role(
        self,
        role_name: str,
        creator_upn: str | None,
        is_system: bool,
        groups_dn: list[str],
    ) -> Role:
        """Create a new role.

        :return: The created Role object.
        """
        groups: list[Group] = await get_groups(
            dn_list=groups_dn,
            session=self._session,
        )
        if not groups:
            raise ValueError("No valid groups provided for the role.")

        role = Role(
            name=role_name,
            creator_upn=creator_upn,
            is_system=is_system,
            groups=groups,
            access_control_entries=[],
        )
        self._session.add(role)
        await self._session.flush()
        return role

    async def update_role(
        self,
        role_id: int,
        role_name: str,
        groups_dn: list[str],
        creator_upn: str | None = None,
        is_system: bool = False,
    ) -> Role:
        """Update an existing role.

        :param role_id: ID of the role to update.
        :param role_name: New name for the role.
        :param creator_upn: UPN of the user who created the role.
        :param is_system: Whether the role is a system role.
        :param groups_dn: List of group DNs associated with the role.
        :return: The updated Role object.
        """
        role = await self.get_role(role_id)
        if not role:
            raise ValueError(f"Role with ID {role_id} does not exist.")

        groups: list[Group] = await get_groups(
            dn_list=groups_dn,
            session=self._session,
        )

        if not groups:
            raise ValueError("No valid groups provided for the role.")

        role.name = role_name
        role.creator_upn = creator_upn  # type: ignore
        role.is_system = is_system
        role.groups.clear()
        role.groups.extend(groups)

        await self._session.flush()
        return role

    async def delete_role(
        self,
        role_id: int,
    ) -> None:
        """Delete a role by its ID.

        :param role_id: ID of the role to delete.
        """
        role = await self.get_role(role_id)
        if not role:
            raise ValueError(f"Role with ID {role_id} does not exist.")

        await self._session.delete(role)
        await self._session.flush()

    async def _get_directories_with_scope(
        self,
        base_dn: str,
        scope: RoleScope,
    ) -> list[Directory]:
        """Get directories based on the scope.

        :param base_dn: Base DN to start searching from.
        :param scope: Scope of the role.
        """
        search_path = get_search_path(base_dn)
        if scope == RoleScope.SELF:
            path_filter = get_path_filter(path=search_path)
            directory = await self._session.scalar(
                select(Directory).where(path_filter)
            )
            return [directory] if directory else []

        elif scope == RoleScope.SINGLE_LEVEL:
            query = select(Directory).filter(
                or_(
                    and_(
                        func.cardinality(Directory.path)
                        == len(search_path) + 1,
                        get_path_filter(
                            column=Directory.path[0 : len(search_path)],
                            path=search_path,
                        ),
                    ),
                    get_path_filter(path=search_path),
                )
            )
            return list((await self._session.scalars(query)).all())

        elif scope == RoleScope.WHOLE_SUBTREE:
            path_filter = get_path_filter(
                column=Directory.path[1 : len(search_path)],
                path=search_path,
            )
            return list(
                (
                    await self._session.scalars(
                        select(Directory).where(path_filter)
                    )
                ).all()
            )

        else:
            raise ValueError(f"Invalid scope: {scope}")

    async def add_access_control_entries(
        self,
        role_id: int,
        access_control_entries: list[AccessControlEntrySchema],
    ) -> list[AccessControlEntry]:
        """Add new access control entries to a role.

        :param role_id: ID of the role to add entries to.
        :param access_control_entries: List of access control entries to add.
        :return: List of newly added AccessControlEntry objects.
        """
        role = await self.get_role(role_id)
        if not role:
            raise ValueError(f"Role with ID {role_id} does not exist.")

        directory_cache = {}
        new_aces = []
        for ace in access_control_entries:
            cache_key = (ace.base_dn, ace.scope)
            if cache_key not in directory_cache:
                directory_cache[
                    cache_key
                ] = await self._get_directories_with_scope(
                    base_dn=ace.base_dn,
                    scope=ace.scope,
                )

            new_ace = AccessControlEntry(
                ace_type=ace.ace_type.value,
                depth=get_depth_by_dn(ace.base_dn),
                path=ace.base_dn,
                scope=ace.scope.value,
                entity_type_id=ace.entity_type_id,
                attribute_type_id=ace.attribute_type_id,
                is_allow=ace.is_allow,
                directories=directory_cache[cache_key],
                role=role,
            )
            new_aces.append(new_ace)

        self._session.add_all(new_aces)
        await self._session.flush()

        for single_ace in new_aces:
            await self._session.refresh(
                single_ace, attribute_names=["attribute_type", "entity_type"]
            )

        return new_aces

    async def delete_access_control_entry(self, ace_id: int) -> None:
        """Delete an access control entry from a role.

        :param ace_id: ID of the access control entry to delete.
        """
        ace = await self._session.get(AccessControlEntry, ace_id)
        if not ace:
            raise ValueError(f"ACE with ID {ace_id} does not exist.")

        await self._session.delete(ace)
        await self._session.flush()

    async def get_aces_by_dn(
        self,
        base_dn: GRANT_DN_STRING,
    ) -> list[AccessControlEntry]:
        """Get access control entries by base DN.

        :param base_dn: Base DN to filter access control entries.
        :return: List of AccessControlEntry objects.
        """
        query = (
            select(AccessControlEntry)
            .join(AccessControlEntry.directories)
            .where(Directory.path == get_search_path(base_dn))
            .options(
                joinedload(AccessControlEntry.role),
                joinedload(AccessControlEntry.attribute_type),
                joinedload(AccessControlEntry.entity_type),
            )
        )
        result = await self._session.scalars(query)
        return list(result.all())
