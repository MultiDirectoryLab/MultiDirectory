"""Role DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Callable

from adaptix import P
from adaptix.conversion import get_converter, link_function
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from abstract_dao import AbstractDAO
from ldap_protocol.utils.queries import get_groups
from models import AccessControlEntry, Group, Role

from .access_control_entry_dao import _convert as ace_convert
from .dataclasses import AccessControlEntryDTO, RoleDTO
from .exceptions import NoValidGroupsError, RoleNotFoundError


def make_groups(role: Role) -> list[str]:
    """Create a list of group DNs from a Role object."""
    return [group.directory.get_dn() for group in role.groups]


def make_aces(role: Role) -> list[AccessControlEntryDTO]:
    """Create a list of AccessControlEntryDTO objects from a Role object."""
    return [ace_convert(ace) for ace in role.access_control_entries]


def _convert(include_aces: bool = True) -> Callable[[Role], RoleDTO]:
    """Convert a Role object to a RoleDTO object."""
    ace_f = make_aces if include_aces else (lambda _: None)  # type: ignore
    return get_converter(
        Role,
        RoleDTO,
        recipe=[
            link_function(make_groups, P[RoleDTO].groups),
            link_function(lambda x: x.created_at, P[RoleDTO].created_at),
            link_function(ace_f, P[RoleDTO].access_control_entries),
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

        :param int _id: ID of the role to retrieve.
        :return: Role object.
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

        :param int _id: ID of the role to retrieve.
        :return: RoleDTO object.
        """
        return _convert()(await self._get_raw(_id))

    async def get_by_name(self, role_name: str) -> RoleDTO:
        """Get a role by its name.

        :param role_name: Name of the role to retrieve.
        :return: RoleDTO object.
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
        return _convert()(retval)

    async def get_all(self) -> list[RoleDTO]:
        """Get all roles.

        :return: List of RoleDTO objects.
        """
        roles = (
            await self._session.scalars(
                select(Role).options(
                    selectinload(Role.groups).selectinload(Group.directory),
                ),
            )
        ).all()
        return list(map(_convert(include_aces=False), roles))

    async def create(self, dto: RoleDTO) -> None:
        """Create a new role.

        :param RoleDTO dto: Data transfer object containing role information.
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

    async def update(self, _id: int, dto: RoleDTO) -> None:
        """Update an existing role.

        :param int _id: ID of the role to update.
        :param RoleDTO dto: Data transfer object containing updated
            role information.
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

    async def delete(self, _id: int) -> None:
        """Delete a role by its ID.

        :param int _id: ID of the role to delete.
        """
        role = await self.get(_id)
        await self._session.execute(delete(Role).filter_by(id=role.id))
        await self._session.flush()
