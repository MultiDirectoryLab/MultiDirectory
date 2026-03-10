"""Attribute Value Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from collections import defaultdict
from typing import Callable, cast as tcast

from entities import Attribute, Directory, User
from enums import EntityTypeNames
from ldap_protocol.objects import PartialAttribute

type _AttrNameType = str
type _ValueType = str
type _ValueValidatorType = Callable[[_ValueType], bool]
type _CompiledValidatorsType = dict[
    EntityTypeNames,
    dict[_AttrNameType, _ValueValidatorType],
]


class AttributeValueValidatorError(Exception): ...


# NOTE: Not validate `distinguishedName`, `member` and `memberOf` attributes,
# because it doesn't exist.
_ENTITY_NAME_AND_ATTR_NAME_VALIDATION_MAP: dict[
    tuple[EntityTypeNames, _AttrNameType],
    tuple[str, ...],
] = {
    (EntityTypeNames.ORGANIZATIONAL_UNIT, "name"): (
        "not_start_with_space",
        "not_start_with_hash",
        "not_end_with_space",
        "not_contains_symbols",
    ),
    (EntityTypeNames.GROUP, "name"): (
        "not_start_with_space",
        "not_start_with_hash",
        "not_end_with_space",
        "not_contains_symbols",
    ),
    (EntityTypeNames.USER, "name"): (
        "not_start_with_space",
        "not_start_with_hash",
        "not_end_with_space",
        "not_contains_symbols",
    ),
    (EntityTypeNames.USER, "sAMAccountName"): (
        "not_contains_symbols_ext",
        "not_end_with_dot",
        "not_contains_control_characters",
        "not_contains_at",
    ),
    (EntityTypeNames.COMPUTER, "name"): (
        "not_start_with_space",
        "not_start_with_hash",
        "not_end_with_space",
        "not_contains_symbols",
    ),
    (EntityTypeNames.COMPUTER, "sAMAccountName"): (
        "not_contains_symbols_ext",
        "not_end_with_dot",
        "not_contains_control_characters",
        "not_contains_spaces_and_dots",
        "not_only_numbers",
        "not_start_with_number",
    ),
}


class _ValValidators:
    @staticmethod
    def not_start_with_space(value: _ValueType) -> bool:
        return not value.startswith(" ")

    @staticmethod
    def not_only_numbers(value: _ValueType) -> bool:
        return not value.isdigit()

    @staticmethod
    def not_contains_at(value: _ValueType) -> bool:
        return "@" not in value

    @staticmethod
    def not_start_with_number(value: _ValueType) -> bool:
        return bool(value and not value[0].isdigit())

    @staticmethod
    def not_start_with_hash(value: _ValueType) -> bool:
        return not value.startswith("#")

    @staticmethod
    def not_end_with_space(value: _ValueType) -> bool:
        return not value.endswith(" ")

    @staticmethod
    def not_contains_control_characters(value: _ValueType) -> bool:
        return all(ord(char) >= 32 and ord(char) != 127 for char in value)

    @staticmethod
    def not_contains_spaces_and_dots(value: _ValueType) -> bool:
        return " " not in value and "." not in value

    @staticmethod
    def not_contains_symbols(value: _ValueType) -> bool:
        return not re.search(r'[,+"\\<>;=]', value)

    @staticmethod
    def not_contains_symbols_ext(value: _ValueType) -> bool:
        return not re.search(r'["/\\\[\]:;\|=,\+\*\?<>]', value)

    @staticmethod
    def not_end_with_dot(value: _ValueType) -> bool:
        return not value.endswith(".")


class AttributeValueValidator:
    _compiled_validators: _CompiledValidatorsType

    def __init__(self) -> None:
        self._compiled_validators: _CompiledValidatorsType = (
            self.__compile_validators()
        )

    def __compile_validators(self) -> _CompiledValidatorsType:
        res: _CompiledValidatorsType = defaultdict(dict)

        for (
            key,
            validator_names,
        ) in _ENTITY_NAME_AND_ATTR_NAME_VALIDATION_MAP.items():
            validators = [getattr(_ValValidators, n) for n in validator_names]
            res[key[0]][key[1]] = self.__create_combined_validator(validators)

        return res

    def __create_combined_validator(
        self,
        funcs: list[_ValueValidatorType],
    ) -> _ValueValidatorType:
        def combined(value: _ValueType) -> bool:
            return all(func(value) for func in funcs)

        return combined

    def _get_subset_validators(
        self,
        entity_type_name: EntityTypeNames | str,
    ) -> dict[_AttrNameType, _ValueValidatorType] | None:
        if entity_type_name in self._compiled_validators:
            entity_type_name = tcast("EntityTypeNames", entity_type_name)
        else:
            return None
        return self._compiled_validators.get(entity_type_name)

    def _get_validator(
        self,
        entity_type_name: EntityTypeNames | str,
        attr_name: str,
    ) -> _ValueValidatorType | None:
        subset_validators = self._get_subset_validators(entity_type_name)
        return subset_validators.get(attr_name) if subset_validators else None

    def is_value_valid(
        self,
        entity_type_name: EntityTypeNames | str,
        attr_name: _AttrNameType,
        attr_value: _ValueType,
    ) -> bool:
        validator = self._get_validator(entity_type_name, attr_name)

        if not validator:
            return True

        return validator(attr_value)

    def is_partial_attribute_valid(
        self,
        entity_type_name: EntityTypeNames | str,
        partial_attribute: PartialAttribute,
    ) -> bool:
        validator = self._get_validator(
            entity_type_name,
            partial_attribute.type,
        )

        if not validator:
            return True

        for value in partial_attribute.vals:
            if isinstance(value, str) and not validator(value):
                return False

        return True

    def is_directory_attributes_valid(
        self,
        entity_type_name: EntityTypeNames | str,
        attributes: list[Attribute],
    ) -> bool:
        subset_validators = self._get_subset_validators(entity_type_name)
        if not subset_validators:
            return True

        for attribute in attributes:
            if not attribute.value:
                continue

            validator = subset_validators.get(attribute.name)
            if not validator:
                continue

            if not validator(attribute.value):
                return False

        return True

    def is_directory_valid(self, directory: Directory) -> bool:
        if not directory.entity_type:
            raise AttributeValueValidatorError(
                "Directory must have an entity type",
            )

        entity_type_name = directory.entity_type.name

        if entity_type_name and not self.is_value_valid(
            entity_type_name,
            "name",
            directory.name,
        ):
            return False

        if entity_type_name == EntityTypeNames.USER:
            if not directory.user:
                raise AttributeValueValidatorError(
                    "User directory must have associated User",
                )

            if not self.is_user_valid(directory.user):
                return False

        if not self.is_directory_attributes_valid(  # noqa: SIM103
            entity_type_name,
            directory.attributes,
        ):
            return False

        return True

    def is_user_valid(self, user: User) -> bool:
        user_entity_type_name = EntityTypeNames.USER

        if not self.is_value_valid(
            user_entity_type_name,
            "sAMAccountName",
            user.sam_account_name,
        ):
            return False

        if not self.is_value_valid(  # noqa: SIM103
            user_entity_type_name,
            "userPrincipalName",
            user.user_principal_name,
        ):
            return False

        return True
