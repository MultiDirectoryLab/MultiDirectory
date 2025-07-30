"""Test ACE checks for search access.

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
        ([], 1, (False, set(), set())),  # Empty access control entries list
        (
            [create_mock_ace(is_allow=False, attribute_type_id=None)],
            1,
            (False, set(), set()),
        ),  # Deny all access without attributes
        (
            [create_mock_ace(is_allow=True, attribute_type_id=None)],
            1,
            (True, set(), set()),
        ),  # Allow all access without attributes
        (
            [
                create_mock_ace(
                    is_allow=False,
                    attribute_type_id=1,
                    attribute_type_name="cn",
                ),
                create_mock_ace(is_allow=True, attribute_type_id=None),
            ],
            1,
            (True, {"cn"}, set()),
        ),  # Allow all access but deny one attribute
        (
            [
                create_mock_ace(
                    is_allow=True,
                    attribute_type_id=1,
                    attribute_type_name="cn",
                ),
            ],
            1,
            (True, set(), {"cn"}),
        ),  # Allow one attribute but deny all others
        (
            [
                create_mock_ace(
                    is_allow=False,
                    attribute_type_id=1,
                    attribute_type_name="cn",
                ),
                create_mock_ace(
                    is_allow=True,
                    attribute_type_id=2,
                    attribute_type_name="name",
                ),
                create_mock_ace(
                    is_allow=True,
                    attribute_type_id=2,
                    attribute_type_name="email",
                ),
            ],
            1,
            (True, {"cn"}, {"email", "name"}),
        ),  # Mixed permissions with some forbidden and some allowed attributes
        (
            [
                create_mock_ace(is_allow=False, attribute_type_id=None),
                create_mock_ace(
                    is_allow=True,
                    attribute_type_id=1,
                    attribute_type_name="cn",
                ),
            ],
            1,
            (False, set(), set()),
        ),  # Allow override with deny all access
        (
            [
                create_mock_ace(
                    is_allow=True,
                    attribute_type_id=None,
                    entity_type_id=1,
                ),
            ],
            1,
            (True, set(), set()),
        ),  # Allow access with specific correct entity type
        (
            [
                create_mock_ace(
                    is_allow=False,
                    attribute_type_id=None,
                    entity_type_id=1,
                ),
            ],
            1,
            (False, set(), set()),
        ),  # Deny access with specific correct entity type
        (
            [
                create_mock_ace(
                    is_allow=True,
                    attribute_type_id=None,
                    entity_type_id=2,
                ),
            ],
            1,
            (False, set(), set()),
        ),  # Allow access with incorrect entity type
    ],
)
def test_check_search_access(
    aces: list[AccessControlEntry],
    entity_type_id: int,
    expected_result: tuple[bool, set[str], set[str]],
) -> None:
    """Test the check_search_access method of AccessManager."""
    filtered_aces = AccessManager._filter_aces_by_entity_type(
        aces,
        entity_type_id,
    )
    result = AccessManager._check_search_access(filtered_aces)
    assert result == expected_result


def test_check_search_filter_access() -> None:
    """Test the check_search_filter_attrs method of AccessManager."""
    forbidden_attributes = {"sn"}
    allowed_attributes = {"cn", "mail"}

    # Test with allowed attributes
    result = AccessManager.check_search_filter_attrs(
        {"cn"},
        forbidden_attributes,
        allowed_attributes,
    )
    assert result is True

    # Test with forbidden attributes
    result = AccessManager.check_search_filter_attrs(
        {"sn"},
        forbidden_attributes,
        allowed_attributes,
    )
    assert result is False

    # Test with no attributes
    result = AccessManager.check_search_filter_attrs(
        set(),
        forbidden_attributes,
        allowed_attributes,
    )
    assert result is True

    # Test with allowed and forbidden attributes
    result = AccessManager.check_search_filter_attrs(
        {"cn", "sn"},
        forbidden_attributes,
        allowed_attributes,
    )
    assert result is False
