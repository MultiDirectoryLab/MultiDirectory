"""Role use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from loguru import logger
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import selectinload

from ldap_protocol.roles.enums import AceType, RoleConstants, RoleScope
from ldap_protocol.roles.role_dao import AccessControlEntrySchema, RoleDAO
from ldap_protocol.utils.queries import get_all_users
from models import AccessControlEntry, Directory, Role


class RoleUseCase:
    """Role use case."""

    _role_dao: RoleDAO

    def __init__(self, role_dao: RoleDAO):
        """Initialize RoleUseCase with a database session."""
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
        query = (
            select(AccessControlEntry)
            .join(AccessControlEntry.directories)
            .options(
                selectinload(AccessControlEntry.directories),
            )
            .where(
                Directory.id == parent_directory.id,
                or_(
                    and_(
                        AccessControlEntry.depth != Directory.depth,
                        AccessControlEntry.scope
                        == RoleScope.WHOLE_SUBTREE.value,
                    ),
                    and_(
                        AccessControlEntry.depth == Directory.depth,
                        AccessControlEntry.scope.in_(
                            [
                                RoleScope.SINGLE_LEVEL.value,
                                RoleScope.WHOLE_SUBTREE.value,
                            ]
                        ),
                    ),
                ),
            )
        )

        aces = (await self._role_dao._session.execute(query)).scalars().all()

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
        :param ace_types: List of AceType to filter access control entries.
        :return: List of AccessControlEntry objects.
        """
        query = (
            select(AccessControlEntry)
            .join(AccessControlEntry.directories)
            .where(
                Directory.id == dir_id,
                AccessControlEntry.role_id.in_(user_role_ids),
                AccessControlEntry.ace_type == AceType.PASSWORD_MODIFY.value,
            )
            .order_by(
                AccessControlEntry.depth.asc(),
                AccessControlEntry.is_allow.asc(),
            )
            .limit(1)
        )
        result = await self._role_dao._session.scalar(query)
        return result

    async def add_pwd_modify_ace_for_new_user(
        self,
        new_user_dir: Directory,
    ) -> None:
        """Add password modify access to the Domain Admins Role.

        :param new_user_dir: Directory object for the new user.
        :param session: Database session.
        """
        domain_admins_role = await self._role_dao._session.scalar(
            select(Role)
            .where(Role.name == RoleConstants.DOMAIN_ADMINS_ROLE_NAME)
            .options(selectinload(Role.access_control_entries))
        )
        if not domain_admins_role:
            logger.error("Domain Admins Role not found.")
            return

        new_pwd_ace = AccessControlEntry(
            ace_type=AceType.PASSWORD_MODIFY.value,
            depth=new_user_dir.depth,
            path=new_user_dir.path_dn,
            scope=RoleScope.SELF.value,
            is_allow=True,
            entity_type_id=None,
            attribute_type_id=None,
            directories=[new_user_dir],
        )

        self._role_dao._session.add(new_pwd_ace)
        domain_admins_role.access_control_entries.append(new_pwd_ace)

    async def create_domain_admins_role(self, base_dn: str) -> Role:
        """Create a Domain Admins role with full access."""
        group_dn = RoleConstants.DOMAIN_ADMINS_GROUP_CN + base_dn
        domain_admins_role = await self._role_dao.create_role(
            role_name=RoleConstants.DOMAIN_ADMINS_ROLE_NAME,
            creator_upn=None,
            is_system=True,
            groups_dn=[group_dn],
        )

        aces = await self._build_domain_admins_aces(base_dn)
        await self._role_dao.add_access_control_entries(
            role_id=domain_admins_role.id,
            access_control_entries=aces,
        )

        return domain_admins_role

    async def create_read_only_role(self, base_dn: str) -> Role:
        """Create a Read Only role."""
        group_dn = RoleConstants.READONLY_GROUP_CN + base_dn
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
                base_dn=base_dn,
                attribute_type_id=None,
                entity_type_id=None,
                is_allow=True,
            )
        ]
        await self._role_dao.add_access_control_entries(
            role_id=role.id,
            access_control_entries=aces,
        )

        return role

    async def create_kerberos_system_role(self, base_dn: str) -> Role:
        """Create a Kerberos system role with full access."""
        group_dn = RoleConstants.KERBEROS_GROUP_CN + base_dn
        role = await self._role_dao.create_role(
            role_name=RoleConstants.KERBEROS_ROLE_NAME,
            creator_upn=None,
            is_system=True,
            groups_dn=[group_dn],
        )

        aces = self._get_full_access_aces("ou=services," + base_dn)
        await self._role_dao.add_access_control_entries(
            role_id=role.id,
            access_control_entries=aces,
        )

        return role

    async def _build_domain_admins_aces(
        self, base_dn: str
    ) -> list[AccessControlEntrySchema]:
        aces = self._get_full_access_aces(base_dn)

        all_users = await get_all_users(self._role_dao._session)
        for user in all_users:
            aces.append(
                self._create_password_modify_ace(user.directory.path_dn)
            )

        return aces

    def _get_full_access_aces(
        self,
        base_dn: str,
    ) -> list[AccessControlEntrySchema]:
        """Get a full access ACE."""
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

    def _create_password_modify_ace(
        self,
        user_path_dn: str,
    ) -> AccessControlEntrySchema:
        return AccessControlEntrySchema(
            ace_type=AceType.PASSWORD_MODIFY,
            scope=RoleScope.SELF,
            base_dn=user_path_dn,
            attribute_type_id=None,
            entity_type_id=None,
            is_allow=True,
        )
