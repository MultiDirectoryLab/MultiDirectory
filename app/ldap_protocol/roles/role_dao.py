"""Role DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import get_converter, link_function
from sqlalchemy import and_, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from abstract_dao import AbstractDAO
from enums import RoleScope
from ldap_protocol.utils.helpers import get_depth_by_dn
from ldap_protocol.utils.queries import (
    get_groups,
    get_path_filter,
    get_search_path,
)
from models import AccessControlEntry, Directory, Group, Role

from .dataclasses import AccessControlEntryDTO, RoleDTO
from .exceptions import (
    AccessControlEntryAddError,
    AccessControlEntryNotFoundError,
    NoValidDistinguishedNameError,
    NoValidGroupsError,
    RoleNotFoundError,
)


def make_groups(role: Role) -> list[str]:
    """Create a list of group DNs from a Role object."""
    return [group.directory.get_dn() for group in role.groups]


_convert = get_converter(
    Role,
    RoleDTO,
    recipe=[
        link_function(make_groups, P[RoleDTO].groups),
        link_function(lambda x: x.created_at, P[RoleDTO].created_at),
    ],
)


class RoleDAO(AbstractDAO[RoleDTO]):
    """Role DAO."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Role DAO with a database session."""
        self._session = session

    async def _get_raw(self, _id: int) -> Role:
        """Get a role by its ID.

        :param _id: ID of the role to retrieve.
        :return: Role object if found, None otherwise.
        """
        query = (
            select(Role)
            .options(
                selectinload(Role.groups).selectinload(Group.directory),
                selectinload(Role.access_control_entries).options(
                    joinedload(AccessControlEntry.attribute_type),
                    joinedload(AccessControlEntry.entity_type),
                    joinedload(AccessControlEntry.role),
                ),
            )
            .where(Role.id == _id)
        )
        retval = await self._session.scalar(query)
        if not retval:
            raise RoleNotFoundError(f"Role with ID {_id} does not exist.")
        return retval

    async def get(self, _id: int) -> RoleDTO:
        """Get a role by its ID.

        :param role_id: ID of the role to retrieve.
        :return: Role object if found, None otherwise.
        """
        return _convert(await self._get_raw(_id))

    async def get_by_name(self, role_name: str) -> RoleDTO:
        """Get a role by its name.

        :param role_name: Name of the role to retrieve.
        :return: Role object if found, None otherwise.
        """
        query = (
            select(Role)
            .options(
                selectinload(Role.groups).selectinload(Group.directory),
                selectinload(Role.access_control_entries).options(
                    joinedload(AccessControlEntry.attribute_type),
                    joinedload(AccessControlEntry.entity_type),
                    joinedload(AccessControlEntry.role),
                ),
            )
            .where(Role.name == role_name)
        )
        retval = await self._session.scalar(query)
        if not retval:
            raise RoleNotFoundError(
                f"Role with name {role_name} does not exist.",
            )
        return _convert(retval)

    async def get_all(self) -> list[RoleDTO]:
        """Get all roles.

        :return: List of Role objects.
        """
        roles = (
            await self._session.scalars(
                select(Role)
                .options(
                    selectinload(Role.groups).selectinload(Group.directory),
                ),
            )
        ).all()
        return list(map(_convert, roles))

    async def create(
        self,
        dto: RoleDTO,
    ) -> None:
        """Create a new role.

        :param role_name: Name of the role to create.
        :param creator_upn: UPN of the user who created the role.
        :param is_system: Whether the role is a system role.
        :param groups_dn: List of group DNs associated with the role.
        :return: The created Role object.
        """
        groups: list[Group] = await get_groups(
            dn_list=dto.groups,
            session=self._session,
        )
        if not groups:
            raise NoValidGroupsError("No valid groups provided for the role.")

        role = Role(
            name=dto.name,
            creator_upn=dto.creator_upn,
            is_system=dto.is_system,
            groups=groups,
            access_control_entries=[],
        )
        self._session.add(role)
        await self._session.flush()
        self.last_id = role.id

    def get_last_id(self) -> int:
        """Get the last inserted role ID.

        :return: The last inserted role ID or None if not available.
        """
        try:
            return self.last_id
        finally:
            del self.last_id

    async def update(
        self,
        _id: int,
        dto: RoleDTO,
    ) -> None:
        """Update an existing role.

        :param role_id: ID of the role to update.
        :param role_name: New name for the role.
        :param creator_upn: UPN of the user who created the role.
        :param is_system: Whether the role is a system role.
        :param groups_dn: List of group DNs associated with the role.
        :return: The updated Role object.
        """
        role = await self._get_raw(_id)
        groups: list[Group] = await get_groups(
            dn_list=dto.groups,
            session=self._session,
        )

        if not groups:
            raise NoValidGroupsError("No valid groups provided for the role.")

        role.name = dto.name
        role.creator_upn = dto.creator_upn
        role.is_system = dto.is_system
        role.groups.clear()
        role.groups.extend(groups)

        await self._session.flush()

    async def delete(
        self,
        role_id: int,
    ) -> None:
        """Delete a role by its ID.

        :param role_id: ID of the role to delete.
        """
        role = await self.get(role_id)
        await self._session.execute(delete(Role).filter_by(id=role.id))
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
        if scope == RoleScope.BASE_OBJECT:
            path_filter = get_path_filter(path=search_path)
            directory = await self._session.scalar(
                select(Directory).where(path_filter),
            )
            return [directory] if directory else []

        elif scope == RoleScope.SINGLE_LEVEL:
            query = select(Directory).filter(
                and_(
                    func.cardinality(Directory.path) == len(search_path) + 1,
                    get_path_filter(
                        column=Directory.path[0 : len(search_path)],
                        path=search_path,
                    ),
                ),
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
                        select(Directory).where(path_filter),
                    )
                ).all(),
            )

        else:
            raise ValueError(f"Invalid scope: {scope}")

    async def add_access_control_entries(
        self,
        role_id: int,
        access_control_entries: list[AccessControlEntryDTO],
    ) -> None:
        """Add new access control entries to a role.

        :param role_id: ID of the role to add entries to.
        :param access_control_entries: List of access control entries to add.
        """
        role = await self._get_raw(role_id)

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

            if not directory_cache[cache_key]:
                raise NoValidDistinguishedNameError(
                    f"Invalid distinguished name: {ace.base_dn}",
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
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            raise AccessControlEntryAddError(
                "Failed to add access control entries.",
            )

        for single_ace in new_aces:
            await self._session.refresh(
                single_ace,
                attribute_names=["attribute_type", "entity_type"],
            )

    async def delete_access_control_entry(self, ace_id: int) -> None:
        """Delete an access control entry from a role.

        :param ace_id: ID of the access control entry to delete.
        """
        ace = await self._session.get(AccessControlEntry, ace_id)
        if not ace:
            raise AccessControlEntryNotFoundError(
                f"ACE with ID {ace_id} does not exist.",
            )

        await self._session.delete(ace)
        await self._session.flush()
