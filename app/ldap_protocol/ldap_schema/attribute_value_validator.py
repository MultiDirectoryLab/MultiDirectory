"""Attribute Value Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import defaultdict
from typing import Callable, cast as tcast

from entities import Directory
from enums import EntityTypeNames

type _AttrNameType = str
type _ValueType = str
type _ValueValidatorType = Callable[[_ValueType], bool]
type _CompiledValidatorsType = dict[
    EntityTypeNames,
    dict[_AttrNameType, _ValueValidatorType],
]


# NOTE: Not validate `distinguishedName`, `member` and `memberOf` attributes,
# because it doesn't exist.
_ENTITY_NAME_AND_ATTR_NAME_VALIDATION_MAP: dict[
    tuple[EntityTypeNames, _AttrNameType],
    tuple[str, ...],
] = {
    (EntityTypeNames.ORGANIZATIONAL_UNIT, "name"): (
        "_not_start_with_space",
        "_not_start_with_hash",
        "_not_end_with_space",
        "_not_contains_symbols",
    ),
    (EntityTypeNames.GROUP, "name"): (
        "_not_start_with_space",
        "_not_start_with_hash",
        "_not_end_with_space",
        "_not_contains_symbols",
    ),
    (EntityTypeNames.USER, "name"): (
        "_not_start_with_space",
        "_not_start_with_hash",
        "_not_end_with_space",
        "_not_contains_symbols",
    ),
    (EntityTypeNames.USER, "sAMAccountName"): (
        "_not_contains_symbols_ext",
        "_not_end_with_dot",
        "_not_contains_control_characters",
        "_not_contains_at",
    ),
    (EntityTypeNames.COMPUTER, "name"): (
        "_not_start_with_space",
        "_not_start_with_hash",
        "_not_end_with_space",
        "_not_contains_symbols",
    ),
    (EntityTypeNames.COMPUTER, "sAMAccountName"): (
        "_not_contains_symbols_ext",
        "_not_end_with_dot",
        "_not_contains_control_characters",
        "_not_contains_spaces_and_dots",
        "_not_only_numbers",
        "_not_start_with_number",
    ),
}


class _ValValidators:
    @staticmethod
    def _not_start_with_space(value: _ValueType) -> bool:
        return not value.startswith(" ")

    @staticmethod
    def _not_only_numbers(value: _ValueType) -> bool:
        return not value.isdigit()

    @staticmethod
    def _not_contains_at(value: _ValueType) -> bool:
        return "@" not in value

    @staticmethod
    def _not_start_with_number(value: _ValueType) -> bool:
        return bool(value and not value[0].isdigit())

    @staticmethod
    def _not_start_with_hash(value: _ValueType) -> bool:
        return not value.startswith("#")

    @staticmethod
    def _not_end_with_space(value: _ValueType) -> bool:
        return not value.endswith(" ")

    @staticmethod
    def _not_contains_control_characters(value: _ValueType) -> bool:
        return all(ord(char) >= 32 and ord(char) != 127 for char in value)

    @staticmethod
    def _not_contains_spaces_and_dots(value: _ValueType) -> bool:
        return " " not in value and "." not in value

    @staticmethod
    def _not_contains_symbols(value: _ValueType) -> bool:
        forbidden_symbols = set(',+"\\<>;=')
        return not bool(set(value) & forbidden_symbols)

    @staticmethod
    def _not_contains_symbols_ext(value: _ValueType) -> bool:
        forbidden_symbols = set('"/\\[]:;|=,+*?<>')
        return not bool(set(value) & forbidden_symbols)

    @staticmethod
    def _not_end_with_dot(value: _ValueType) -> bool:
        return not value.endswith(".")


class AttributeValueValidator:
    """Validator for attribute values for different entity types."""

    _compiled_validators: _CompiledValidatorsType

    def __init__(self) -> None:
        """Initialize AttributeValueValidator."""
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

    def validate_value(
        self,
        entity_type_name: EntityTypeNames | str,
        attr_name: _AttrNameType,
        value: _ValueType,
    ) -> bool:
        if entity_type_name not in self._compiled_validators:
            return True

        entity_type_name = tcast("EntityTypeNames", entity_type_name)

        validator = self._compiled_validators.get(entity_type_name, {}).get(attr_name)  # noqa: E501  # fmt: skip

        if not validator:
            return True

        return validator(value)

    def validate_directory(self, directory: Directory) -> bool:
        """Validate all directory attributes."""
        if not directory.entity_type:
            raise ValueError("Directory must have an entity type")

        entity_type_name = directory.entity_type.name
        if entity_type_name not in EntityTypeNames:
            return True

        entity_type_name = tcast("EntityTypeNames", entity_type_name)

        if not self.validate_value(entity_type_name, "name", directory.name):
            return False

        if entity_type_name == EntityTypeNames.USER:
            if not directory.user:
                raise ValueError("User directory must have associated User")

            if not self.validate_value(
                entity_type_name,
                "sAMAccountName",
                directory.user.sam_account_name,
            ):
                return False
            if not self.validate_value(
                entity_type_name,
                "userPrincipalName",
                directory.user.user_principal_name,
            ):
                return False

        for attr in directory.attributes:
            if attr.value and not self.validate_value(
                entity_type_name,
                attr.name,
                attr.value,
            ):
                return False

        return True
