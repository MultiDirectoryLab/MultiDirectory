"""Test ACE checks for entity-level access.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest

from ldap_protocol.roles.access_manager import AccessManager
from models import AccessControlEntry

from .conftest import create_mock_ace


@pytest.mark.parametrize(
    ("aces", "entity_type_id", "expected_result"),
    [
        ([], 1, False),  # Empty access control entries list
        (
            [create_mock_ace(is_allow=False, entity_type_id=None)],
            1,
            False,
        ),  # Deny all access without entity type
        (
            [create_mock_ace(is_allow=True, entity_type_id=None)],
            1,
            True,
        ),  # Allow all access without entity type
        (
            [
                create_mock_ace(
                    is_allow=True,
                    entity_type_id=1,
                ),
            ],
            1,
            True,
        ),  # Allow entity type 1
        (
            [
                create_mock_ace(
                    is_allow=False,
                    entity_type_id=1,
                )
            ],
            1,
            False,
        ),  # Deny entity type 1
        (
            [create_mock_ace(is_allow=False, entity_type_id=2)],
            1,
            False,
        ),  # Deny entity type 2 when checking entity type 1
        (
            [create_mock_ace(is_allow=True, entity_type_id=None)],
            None,
            True,
        ),  # Allow all access without entity type
    ],
)
def test_check_entity_level_access(
    aces: list[AccessControlEntry],
    entity_type_id: int | None,
    expected_result: bool,
) -> None:
    """Test entity-level access checks."""
    result = AccessManager.check_entity_level_access(aces, entity_type_id)
    assert result == expected_result
