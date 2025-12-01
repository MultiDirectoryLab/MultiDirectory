"""Attribute Value Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Callable

from constants import EntityTypeNameType

type _ValueType = str

_ENTITY_NAME_AND_ATTR_NAME_VALIDATION_MAP: dict[
    tuple[EntityTypeNameType, str],
    tuple[str, ...],
] = {
    ("Organizational Unit", "name"): (
        "_not_start_with_space",
        "_not_start_with_hash",
        "_not_end_with_space",
        "_not_contains_symbols",
    ),
    ("Group", "name"): (
        "_not_start_with_space",
        "_not_start_with_hash",
        "_not_end_with_space",
        "_not_contains_symbols",
    ),
    ("User", "name"): (
        "_not_start_with_space",
        "_not_start_with_hash",
        "_not_end_with_space",
        "_not_contains_symbols",
    ),
    ("User", "sAMAccountName"): (
        "_not_contains_symbols2",
        "_not_end_with_dot",
        "_not_contains_control_characters",
        "_not_contains_at",
    ),
    ("Computer", "name"): (
        "_not_start_with_space",
        "_not_start_with_hash",
        "_not_end_with_space",
        "_not_contains_symbols",
    ),
    ("Computer", "sAMAccountName"): (
        "_not_contains_symbols2",
        "_not_end_with_dot",
        "_not_contains_control_characters",
        "_not_contains_spaces_and_dots",
        "_not_only_numbers",
        "_not_start_with_number",
    ),
}


class AttributeValueValidator:
    """Validator for attribute values for different entity types."""

    def __init__(self) -> None:
        """Initialize AttributeValueValidator."""
        self._compiled_validators: dict[
            tuple[EntityTypeNameType, str],
            Callable[[_ValueType], bool],
        ] = {}
        self._compile_validators()

    def _compile_validators(self) -> None:
        for (
            key,
            validator_names,
        ) in _ENTITY_NAME_AND_ATTR_NAME_VALIDATION_MAP.items():
            # Получаем ссылки на функции-валидаторы
            validator_funcs = [getattr(self, name) for name in validator_names]

            # Создаем скомпилированную функцию-валидатор
            def create_combined_validator(
                funcs: list[Callable[[_ValueType], bool]],
            ) -> Callable[[_ValueType], bool]:
                def combined(value: _ValueType) -> bool:
                    return all(func(value) for func in funcs)

                return combined

            self._compiled_validators[key] = create_combined_validator(
                validator_funcs,
            )

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
        return not value[0].isdigit()

    @staticmethod
    def _not_start_with_hash(value: _ValueType) -> bool:
        return not value.startswith("#")

    @staticmethod
    def _not_end_with_space(value: _ValueType) -> bool:
        return not value.endswith(" ")

    @staticmethod
    def _not_contains_control_characters(value: _ValueType) -> bool:
        return all(32 <= ord(char) <= 126 for char in value)

    def _not_contains_spaces_and_dots(self, value: _ValueType) -> bool:
        return " " not in value and "." not in value

    @staticmethod
    def _not_contains_symbols(value: _ValueType) -> bool:
        forbidden_symbols = set(',+"\\<>;=')
        return not bool(set(value) & forbidden_symbols)

    @staticmethod
    def _not_contains_symbols2(value: _ValueType) -> bool:
        forbidden_symbols = set('"/\\[]:;|=,+*?<>')
        return not bool(set(value) & forbidden_symbols)

    @staticmethod
    def _not_end_with_dot(value: _ValueType) -> bool:
        return not value.endswith(".")

    def validate_value(
        self,
        entity_type_name: EntityTypeNameType,
        attr_name: str,
        value: _ValueType,
    ) -> bool:
        validator = self._compiled_validators.get(
            (entity_type_name, attr_name),
        )

        if not validator:
            return True

        return validator(value)
