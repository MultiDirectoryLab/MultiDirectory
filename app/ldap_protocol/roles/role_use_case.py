"""Role use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import StrEnum

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import selectinload

from enums import RoleScope
from ldap_protocol.roles.role_dao import AccessControlEntrySchema, RoleDAO
from ldap_protocol.utils.queries import get_base_directories
from models import AccessControlEntry, AceType, Directory, Role


class RoleConstants(StrEnum):
    """Role constants."""

    DOMAIN_ADMINS_ROLE_NAME = "Domain Admins Role"
    READ_ONLY_ROLE_NAME = "Read Only Role"
    KERBEROS_ROLE_NAME = "Kerberos Role"

    DOMAIN_ADMINS_GROUP_CN = "cn=domain admins,cn=groups,"
    READONLY_GROUP_CN = "cn=readonly domain controllers,cn=groups,"
    KERBEROS_GROUP_CN = "cn=krbadmin,cn=groups,"


class RoleUseCase:
    """Role use case."""

    _role_dao: RoleDAO

    def __init__(self, role_dao: RoleDAO) -> None:
        """Initialize RoleUseCase with a database session.

        :param role_dao: RoleDAO instance for database operations.
        """
        self._role_dao = role_dao

    async def inherit_parent_aces(
        self,
        parent_directory: Directory,
        directory: Directory,
    ) -> None:
        """Inherit access control entries from the parent directory.

        :param parent_directory: Parent directory from which to inherit ACES.
        :param directory: Directory to which the ACES will be added.
        """
        directory_filter = Directory.id == parent_directory.id

        subtree_inheritance = and_(
            AccessControlEntry.depth != Directory.depth,
            AccessControlEntry.scope == RoleScope.WHOLE_SUBTREE,
        )

        explicit_inheritance = and_(
            AccessControlEntry.depth == Directory.depth,
            AccessControlEntry.scope.in_(
                [
                    RoleScope.SINGLE_LEVEL,
                    RoleScope.WHOLE_SUBTREE,
                ]
            ),
        )

        inheritance_conditions = or_(subtree_inheritance, explicit_inheritance)

        query = (
            select(AccessControlEntry)
            .join(AccessControlEntry.directories)
            .options(
                selectinload(AccessControlEntry.directories),
            )
            .where(directory_filter, inheritance_conditions)
        )

        aces = (await self._role_dao._session.execute(query)).scalars().all()  # noqa: SLF001

        for ace in aces:
            ace.directories.append(directory)

    async def get_password_ace(
        self,
        dir_id: int,
        user_role_ids: list[int],
    ) -> AccessControlEntry | None:
        """Get access control entries by directory ID.

        :param dir_id: Directory ID to filter access control entries.
        :param user_role_ids: List of user role IDs.
        :return: List of AccessControlEntry objects.
        """
        query = (
            select(AccessControlEntry)
            .join(AccessControlEntry.directories)
            .where(
                Directory.id == dir_id,
                AccessControlEntry.role_id.in_(user_role_ids),
                AccessControlEntry.ace_type == AceType.PASSWORD_MODIFY,
            )
            .order_by(
                AccessControlEntry.depth.asc(),
                AccessControlEntry.is_allow.asc(),
            )
            .limit(1)
        )
        result = await self._role_dao._session.scalar(query)  # noqa: SLF001
        return result

    async def contains_domain_admins_role(
        self,
        user_role_ids: list[int],
    ) -> bool:
        """Check if the user has the Domain Admins role.

        :param user_role_ids: List of user role IDs.
        :return: True if the user has the Domain Admins role, False otherwise.
        """
        query = (
            select(Role)
            .where(
                Role.id.in_(user_role_ids),
                Role.name == RoleConstants.DOMAIN_ADMINS_ROLE_NAME,
            )
            .limit(1)
            .exists()
        )

        return bool(
            (await self._role_dao._session.scalars(select(query))).one()  # noqa: SLF001
        )

    async def create_domain_admins_role(self) -> None:
        """Create a Domain Admins role with full access.

        :param base_dn: Base DN for the role.
        :return: The created Role object.
        """
        base_dn_list = await get_base_directories(self._role_dao._session)  # noqa: SLF001
        if not base_dn_list:
            return

        group_dn = (
            RoleConstants.DOMAIN_ADMINS_GROUP_CN + base_dn_list[0].path_dn
        )
        domain_admins_role = await self._role_dao.create_role(
            role_name=RoleConstants.DOMAIN_ADMINS_ROLE_NAME,
            creator_upn=None,
            is_system=True,
            groups_dn=[group_dn],
        )

        aces = self._get_full_access_aces(base_dn_list[0].path_dn)
        await self._role_dao.add_access_control_entries(
            role_id=domain_admins_role.id,
            access_control_entries=aces,
        )

    async def create_read_only_role(self) -> None:
        """Create a Read Only role."""
        base_dn_list = await get_base_directories(self._role_dao._session)  # noqa: SLF001
        if not base_dn_list:
            return

        group_dn = RoleConstants.READONLY_GROUP_CN + base_dn_list[0].path_dn
        role = await self._role_dao.create_role(
            role_name=RoleConstants.READ_ONLY_ROLE_NAME,
            creator_upn=None,
            is_system=True,
            groups_dn=[group_dn],
        )

        aces = [
            AccessControlEntrySchema(
                ace_type=AceType.READ,
                scope=RoleScope.WHOLE_SUBTREE,
                base_dn=base_dn_list[0].path_dn,
                attribute_type_id=None,
                entity_type_id=None,
                is_allow=True,
            )
        ]
        await self._role_dao.add_access_control_entries(
            role_id=role.id,
            access_control_entries=aces,
        )

    async def create_kerberos_system_role(self) -> None:
        """Create a Kerberos system role with full access.

        :return: The created Role object.
        """
        base_dn_list = await get_base_directories(self._role_dao._session)  # noqa: SLF001
        if not base_dn_list:
            return

        group_dn = RoleConstants.KERBEROS_GROUP_CN + base_dn_list[0].path_dn
        role = await self._role_dao.create_role(
            role_name=RoleConstants.KERBEROS_ROLE_NAME,
            creator_upn=None,
            is_system=True,
            groups_dn=[group_dn],
        )

        aces = self._get_full_access_aces(
            "ou=services," + base_dn_list[0].path_dn
        )
        await self._role_dao.add_access_control_entries(
            role_id=role.id,
            access_control_entries=aces,
        )

    async def delete_kerberos_system_role(self) -> None:
        """Delete the Kerberos system role."""
        role = await self._role_dao.get_role_by_name(
            RoleConstants.KERBEROS_ROLE_NAME
        )
        if role:
            await self._role_dao.delete_role(role.id)

    def _get_full_access_aces(
        self,
        base_dn: str,
    ) -> list[AccessControlEntrySchema]:
        """Get a full access ACE.

        :param base_dn: Base DN for the role.
        :return: List of AccessControlEntrySchema objects with full access.
        """
        return [
            AccessControlEntrySchema(
                ace_type=AceType.READ,
                scope=RoleScope.WHOLE_SUBTREE,
                base_dn=base_dn,
                attribute_type_id=None,
                entity_type_id=None,
                is_allow=True,
            ),
            AccessControlEntrySchema(
                ace_type=AceType.CREATE_CHILD,
                scope=RoleScope.WHOLE_SUBTREE,
                base_dn=base_dn,
                attribute_type_id=None,
                entity_type_id=None,
                is_allow=True,
            ),
            AccessControlEntrySchema(
                ace_type=AceType.WRITE,
                scope=RoleScope.WHOLE_SUBTREE,
                base_dn=base_dn,
                attribute_type_id=None,
                entity_type_id=None,
                is_allow=True,
            ),
            AccessControlEntrySchema(
                ace_type=AceType.DELETE,
                scope=RoleScope.WHOLE_SUBTREE,
                base_dn=base_dn,
                attribute_type_id=None,
                entity_type_id=None,
                is_allow=True,
            ),
        ]
