"""Role DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import ConversionRetort, link_function
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from abstract_dao import AbstractDAO
from entities import AccessControlEntry, Group, Role
from enums import AuthorizationRules, RoleConstants
from ldap_protocol.utils.queries import get_groups
from repo.pg.tables import queryable_attr as qa

from .ace_dao import _convert as ace_convert
from .dataclasses import AccessControlEntryDTO, RoleDTO
from .exceptions import NoValidGroupsError, RoleNotFoundError


def make_groups(role: Role) -> list[str]:
    """Create a list of group DNs from a Role object."""
    return [group.directory.get_dn() for group in role.groups]


def make_aces(role: Role) -> list[AccessControlEntryDTO]:
    """Create a list of AccessControlEntryDTO objects from a Role object."""
    return [ace_convert(ace) for ace in role.access_control_entries]


base_retort = ConversionRetort(
    recipe=[
        link_function(make_groups, P[RoleDTO].groups),
    ],
)

retort = base_retort.extend(
    recipe=[
        link_function(make_aces, P[RoleDTO].access_control_entries),
    ],
)

retort_without_ace = base_retort.extend(
    recipe=[
        link_function(lambda _: None, P[RoleDTO].access_control_entries),
    ],
)

_convert = retort.get_converter(Role, RoleDTO)
_convert_without_aces = retort_without_ace.get_converter(Role, RoleDTO)


class RoleDAO(AbstractDAO[RoleDTO, int]):
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
                selectinload(qa(Role.groups)).selectinload(
                    qa(Group.directory),
                ),
                selectinload(qa(Role.access_control_entries)).options(
                    joinedload(qa(AccessControlEntry.attribute_type)),
                    joinedload(qa(AccessControlEntry.entity_type)),
                    joinedload(qa(AccessControlEntry.role)),
                ),
            )
            .filter_by(id=_id)
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
        return _convert(await self._get_raw(_id))

    async def get_by_name(self, role_name: str) -> RoleDTO:
        """Get a role by its name.

        :param role_name: Name of the role to retrieve.
        :return: RoleDTO object.
        """
        query = (
            select(Role)
            .options(
                selectinload(qa(Role.groups)).selectinload(
                    qa(Group.directory),
                ),
                selectinload(qa(Role.access_control_entries)).options(
                    joinedload(qa(AccessControlEntry.attribute_type)),
                    joinedload(qa(AccessControlEntry.entity_type)),
                    joinedload(qa(AccessControlEntry.role)),
                ),
            )
            .filter_by(name=role_name)
        )
        retval = await self._session.scalar(query)
        if not retval:
            raise RoleNotFoundError(
                f"Role with name {role_name} does not exist.",
            )
        return _convert(retval)

    async def get_all(self) -> list[RoleDTO]:
        """Get all roles.

        :return: List of RoleDTO objects.
        """
        roles = (
            await self._session.scalars(
                select(Role).options(
                    selectinload(qa(Role.groups)).selectinload(
                        qa(Group.directory),
                    ),
                ),
            )
        ).all()
        return list(map(_convert_without_aces, roles))

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
            permissions=dto.permissions,
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
        role = await self._get_raw(_id)
        await self._session.execute(delete(Role).filter_by(id=role.id))
        await self._session.flush()

    async def update_admin_role_permissions(self) -> None:
        """Update role permissions.

        :param int _id: ID of the role to update.
        :param int permissions: New permissions value.
        """
        query = (
            select(Role)
            .filter_by(name=RoleConstants.DOMAIN_ADMINS_ROLE_NAME)
        )  # fmt: skip
        role = (await self._session.scalars(query)).first()
        if not role:
            return

        role.permissions = AuthorizationRules.get_all()
        await self._session.flush()
