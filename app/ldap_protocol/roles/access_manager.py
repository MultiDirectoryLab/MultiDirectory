"""Access Control Manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from sqlalchemy import Select, and_
from sqlalchemy.orm import selectinload, with_loader_criteria

from enums import AceType, RoleScope
from ldap_protocol.objects import Changes, Operation
from models import AccessControlEntry, Directory


class AccessManager:
    """Manager for access control entries."""

    @classmethod
    def check_search_access(
        cls,
        directory: Directory,
        user_dn: str,
    ) -> tuple[bool, set, set]:
        """Check if search access is allowed based on access control entries.

        :param directory: Directory object to check access for.
        :param user_dn: Distinguished Name of the user.
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
        forbidden_attributes: set[str] = set()
        allowed_attributes: set[str] = set()

        if not aces:
            return False, set(), set()

        for ace in aces:
            if not ace.is_allow and ace.attribute_type_id is None:
                if allowed_attributes:
                    return True, set(), allowed_attributes
                else:
                    return False, set(), set()

            elif not ace.is_allow and ace.attribute_type_id is not None:
                forbidden_attributes.add(ace.attribute_type_name)  # type: ignore

            elif ace.is_allow and ace.attribute_type_id is None:
                return True, forbidden_attributes, set()

            else:
                allowed_attributes.add(ace.attribute_type_name)  # type: ignore

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
        if not filter_attrs or filter_attrs == {"objectclass"}:
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
        :param entity_type_id: ID of the entity type.
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
                    attr_name,
                    filtered_aces,
                    AceType.WRITE,
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
        :param ace_type: Type of access control entry (write or delete).
        :return: True if access is allowed, False otherwise.
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

    @classmethod
    def _get_effective_aces(
        cls,
        directory: Directory,
        user_dn: str,
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

        :param directory: Directory object.
        :param aces: List of access control entries.
        :return: Updated list of access control entries.
        """
        result_aces_list = []
        self_read_ace = AccessControlEntry(
            ace_type=AceType.READ,
            depth=directory.depth,
            path=directory.path_dn,
            scope=RoleScope.BASE_OBJECT,
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

    @staticmethod
    def mutate_query_with_ace_load(
        user_role_ids: list[int],
        query: Select,
        ace_types: list[AceType],
        load_attribute_type: bool = False,
        require_attribute_type_null: bool = False,
    ) -> Select:
        """Mutate query to load access control entries.

        :param user_role_ids: list of user role ids
        :param query: SQLAlchemy query to mutate
        :param ace_types: single AceType or list of AceTypes to filter by
        :param load_attribute_type: whether to joinedload attribute_type
        :param require_attribute_type_null: whether to filter by
            null attribute_type_id
        :return: mutated query with access control entries loaded
        """
        selectin_loader = selectinload(Directory.access_control_entries)
        if load_attribute_type:
            selectin_loader = selectin_loader.joinedload(
                AccessControlEntry.attribute_type
            )

        criteria_conditions = [
            AccessControlEntry.role_id.in_(user_role_ids),
        ]

        if len(ace_types) == 1:
            criteria_conditions.append(
                AccessControlEntry.ace_type == ace_types[0]  # type: ignore
            )
        else:
            criteria_conditions.append(
                AccessControlEntry.ace_type.in_(ace_types)
            )

        if require_attribute_type_null:
            criteria_conditions.append(
                AccessControlEntry.attribute_type_id.is_(None)
            )

        return query.options(
            selectin_loader,
            with_loader_criteria(
                AccessControlEntry,
                and_(*criteria_conditions),
            ),
        )
