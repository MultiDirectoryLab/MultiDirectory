"""Tests for ErrorCode enum uniqueness.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import Counter

from enums import ErrorCode


class TestErrorCodeUniqueness:
    """Test that all ErrorCode values are unique."""

    def test_all_error_code_values_are_unique(self) -> None:
        """Test that all ErrorCode enum values are unique."""
        values = [error_code.value for error_code in ErrorCode]
        value_counts = Counter(values)

        duplicates = {
            value: count for value, count in value_counts.items() if count > 1
        }

        assert not duplicates, (
            f"Found duplicate ErrorCode values: {duplicates}. "
            f"Each error code must have a unique numeric value."
        )

    def test_all_error_code_names_are_unique(self) -> None:
        """Test that all ErrorCode enum names are unique."""
        names = [error_code.name for error_code in ErrorCode]
        name_counts = Counter(names)

        duplicates = {
            name: count for name, count in name_counts.items() if count > 1
        }

        assert not duplicates, (
            f"Found duplicate ErrorCode names: {duplicates}. "
            f"Each error code must have a unique name."
        )
