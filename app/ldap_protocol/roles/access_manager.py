"""Access Control Manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from loguru import logger
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.objects import Changes, Operation
from ldap_protocol.roles.enums import AceType, RoleConstants, RoleScope
from models import AccessControlEntry, Directory, Role


class AccessManager:
    """Manager for access control entries."""

    @classmethod
    def check_search_access(
        cls,
        directory: Directory,
        user_dn: str,
    ) -> tuple[bool, set | None, set | None]:
        """Check if search access is allowed based on access control entries.

        :param aces: List of access control entries.
        :return: Tuple containing a boolean indicating if access is allowed,
            a set of forbidden attributes, and a set of allowed attributes.
        """
        aces = cls._get_effective_aces(
            directory=directory,
            user_dn=user_dn,
        )
        return cls._check_search_access(aces=aces)

    @staticmethod
    def _check_search_access(
        aces: list[AccessControlEntry],
    ) -> tuple[bool, set, set]:
        """Check if search access is allowed based on access control entries.

        :param aces: List of access control entries.
        :return: Tuple containing a boolean indicating if access is allowed,
            a set of forbidden attributes, and a set of allowed attributes.
        """
        forbidden_attributes = set()
        allowed_attributes = set()

        if not aces:
            return False, set(), set()

        for ace in aces:

            if not ace.is_allow and ace.attribute_type_id is None:

                if allowed_attributes:  # type: ignore
                    return True, set(), allowed_attributes
                else:
                    return False, set(), set()

            elif not ace.is_allow and ace.attribute_type_id is not None:
                forbidden_attributes.add(ace.attribute_type_name)

            elif ace.is_allow and ace.attribute_type_id is None:
                return True, forbidden_attributes, set()  # type: ignore

            else:
                allowed_attributes.add(ace.attribute_type_name)

        if not allowed_attributes:
            return False, set(), set()

        return True, forbidden_attributes, allowed_attributes

    @staticmethod
    def check_search_filter_attrs(
        filter_attrs: set[str],
        forbidden_attributes: set[str],
        allowed_attributes: set[str],
    ) -> bool:
        """Check if filter attributes are allowed based on access control.

        :param filter_attrs: Set of attributes to check.
        :param forbidden_attributes: Set of forbidden attributes.
        :param allowed_attributes: Set of allowed attributes.
        :return: True if the filter attributes are allowed, False otherwise.
        """
        if not filter_attrs:
            return True

        if forbidden_attributes and not filter_attrs.isdisjoint(
            forbidden_attributes
        ):
            return False

        return not (
            allowed_attributes
            and not filter_attrs.issubset(allowed_attributes)
        )

    @classmethod
    def check_modify_access(
        cls,
        changes: list[Changes],
        aces: list[AccessControlEntry],
        entity_type_id: int,
    ) -> bool:
        """Check if modify access is allowed based on access control entries.

        :param changes: List of changes to be made.
        :param aces: List of access control entries.
        :return: True if the modify is allowed, False otherwise.
        """
        filtered_aces = cls._filter_aces_by_entity_type(
            aces=aces,
            entity_type_id=entity_type_id,
        )

        if not filtered_aces:
            return False

        for change in changes:
            attr_name = change.get_name()
            if change.operation == Operation.DELETE:
                if not cls._check_modify_access(
                    attr_name,
                    filtered_aces,
                    AceType.DELETE,
                ):
                    return False
            elif change.operation == Operation.ADD:
                if not cls._check_modify_access(
                    attr_name, aces, AceType.WRITE
                ):
                    return False
            else:
                if not (
                    cls._check_modify_access(
                        attr_name,
                        filtered_aces,
                        AceType.WRITE,
                    )
                    and cls._check_modify_access(
                        attr_name,
                        filtered_aces,
                        AceType.DELETE,
                    )
                ):
                    return False

        return True

    @staticmethod
    def _check_modify_access(
        attr_name: str,
        aces: list[AccessControlEntry],
        ace_type: Literal[AceType.WRITE, AceType.DELETE],
    ) -> bool:
        """Check if modify access is allowed for a specific attribute.

        :param attr_name: Name of the attribute to be modified.
        :param aces: List of access control entries.
        :param entity_type_id: ID of the entity type.
        :param ace_type: Type of access control entry (write or delete).
        """
        for ace in aces:
            if (
                ace.ace_type == ace_type
                and not ace.is_allow
                and (
                    ace.attribute_type_id is None
                    or attr_name == ace.attribute_type_name
                )
            ):
                return False
            elif (
                ace.ace_type == ace_type
                and ace.is_allow
                and (
                    ace.attribute_type_id is None
                    or attr_name == ace.attribute_type_name
                )
            ):
                return True

        return False

    @staticmethod
    def check_entity_level_access(
        aces: list[AccessControlEntry],
        entity_type_id: int | None,
    ) -> bool:
        """Check if access is allowed at the entity level (ADD and DELETE).

        :param aces: List of access control entries.
        :param entity_type_id: ID of the entity type.
        :return: True if access is allowed, False otherwise.
        """
        if not aces:
            return False

        for ace in aces:
            if not ace.is_allow and (
                ace.entity_type_id is None
                or ace.entity_type_id == entity_type_id
            ):
                return False

            elif ace.is_allow and (
                ace.entity_type_id is None
                or ace.entity_type_id == entity_type_id
            ):
                return True

        return False

    @staticmethod
    async def inherit_parent_aces(
        parent_directory: Directory,
        directory: Directory,
        session: AsyncSession,
    ) -> None:
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

        aces = (await session.execute(query)).scalars().all()
        logger.critical(f"parent aces: {aces}")

        for ace in aces:
            ace.directories.append(directory)

    @staticmethod
    async def add_pwd_modify_access_for_new_user(
        new_user_dir: Directory,
        session: AsyncSession,
    ) -> None:
        """Add password modify access to the Domain Admins Role.

        :param new_user_dir: Directory object for the new user.
        :param session: Database session.
        """
        domain_admins_role = await session.scalar(
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

        session.add(new_pwd_ace)
        domain_admins_role.access_control_entries.append(new_pwd_ace)

    @classmethod
    def _get_effective_aces(
        cls, directory: Directory, user_dn: str
    ) -> list[AccessControlEntry]:
        """Get effective access control entries for a directory.

        :param directory: Directory object.
        :param user_dn: Distinguished Name of the user.
        :return: List of effective access control entries.
        """
        filtered_aces = cls._filter_aces_by_entity_type(
            aces=directory.access_control_entries,
            entity_type_id=directory.entity_type_id,
        )

        if directory.user and directory.path_dn == user_dn:
            return cls._extend_user_self_read_ace(
                directory=directory,
                aces=filtered_aces,
            )

        return filtered_aces

    @staticmethod
    def _filter_aces_by_entity_type(
        aces: list[AccessControlEntry],
        entity_type_id: int | None,
    ) -> list[AccessControlEntry]:
        """Filter access control entries by entity type ID.

        :param aces: List of access control entries.
        :param entity_type_id: ID of the entity type to filter by.
        :return: Filtered list of access control entries.
        """
        return [
            ace
            for ace in aces
            if ace.entity_type_id is None
            or ace.entity_type_id == entity_type_id
        ]

    @staticmethod
    def _extend_user_self_read_ace(
        directory: Directory,
        aces: list[AccessControlEntry],
    ) -> list[AccessControlEntry]:
        """Extend user self-read ACEs to include all attributes.

        :param aces: List of access control entries.
        :return: Updated list of access control entries.
        """
        result_aces_list = []
        self_read_ace = AccessControlEntry(
            ace_type=AceType.READ.value,
            depth=directory.depth,
            path=directory.path_dn,
            scope=RoleScope.SELF.value,
            is_allow=True,
            entity_type_id=None,
            attribute_type_id=None,
        )

        if not aces:
            return [self_read_ace]

        self_read_ace_inserted = False
        for ace in aces:
            if not self_read_ace_inserted and ace.depth != directory.depth:
                result_aces_list.append(self_read_ace)
                self_read_ace_inserted = True
            result_aces_list.append(ace)

        return result_aces_list
