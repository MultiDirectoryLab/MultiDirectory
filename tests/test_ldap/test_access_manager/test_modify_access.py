"""Test ACE checks for modify access.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from enums import AceType

from ldap_protocol.ldap_responses import PartialAttribute
from ldap_protocol.objects import Changes, Operation
from ldap_protocol.roles.access_manager import AccessManager
from models import AccessControlEntry

from .conftest import create_mock_ace


@pytest.mark.parametrize(
    ("aces", "changes", "entity_type_id", "expected_result"),
    [
        (
            [],
            [
                Changes(
                    operation=Operation.DELETE,
                    modification=PartialAttribute(type="cn", vals="value"),
                )
            ],
            1,
            False,
        ),
        (
            [create_mock_ace(is_allow=False, entity_type_id=None)],
            [
                Changes(
                    operation=Operation.DELETE,
                    modification=PartialAttribute(type="cn", vals="value"),
                )
            ],
            1,
            False,
        ),
        (
            [
                create_mock_ace(
                    ace_type=AceType.DELETE,
                    is_allow=True,
                    entity_type_id=None,
                ),
                create_mock_ace(
                    ace_type=AceType.WRITE,
                    is_allow=True,
                    entity_type_id=None,
                ),
            ],
            [
                Changes(
                    operation=Operation.DELETE,
                    modification=PartialAttribute(type="cn", vals="value"),
                ),
                Changes(
                    operation=Operation.ADD,
                    modification=PartialAttribute(
                        type="description", vals="v"
                    ),
                ),
            ],
            1,
            True,
        ),
        (
            [
                create_mock_ace(
                    ace_type=AceType.DELETE,
                    is_allow=False,
                ),
                create_mock_ace(
                    ace_type=AceType.WRITE,
                    is_allow=True,
                ),
            ],
            [
                Changes(
                    operation=Operation.DELETE,
                    modification=PartialAttribute(type="cn", vals="value"),
                ),
                Changes(
                    operation=Operation.ADD,
                    modification=PartialAttribute(
                        type="description", vals="v"
                    ),
                ),
            ],
            1,
            False,
        ),
        (
            [
                create_mock_ace(
                    ace_type=AceType.DELETE,
                    is_allow=True,
                    entity_type_id=1,
                    attribute_type_id=1,
                    attribute_type_name="cn",
                ),
                create_mock_ace(
                    ace_type=AceType.WRITE,
                    is_allow=True,
                    entity_type_id=1,
                    attribute_type_id=1,
                    attribute_type_name="description",
                ),
            ],
            [
                Changes(
                    operation=Operation.DELETE,
                    modification=PartialAttribute(type="cn", vals="value"),
                ),
                Changes(
                    operation=Operation.ADD,
                    modification=PartialAttribute(
                        type="description", vals="v"
                    ),
                ),
            ],
            1,
            True,
        ),
        (
            [
                create_mock_ace(
                    ace_type=AceType.DELETE,
                    is_allow=True,
                    entity_type_id=1,
                    attribute_type_id=1,
                    attribute_type_name="cn",
                ),
                create_mock_ace(
                    ace_type=AceType.WRITE,
                    is_allow=True,
                    entity_type_id=1,
                    attribute_type_id=1,
                    attribute_type_name="cn",
                ),
            ],
            [
                Changes(
                    operation=Operation.DELETE,
                    modification=PartialAttribute(type="cn", vals="value"),
                ),
                Changes(
                    operation=Operation.ADD,
                    modification=PartialAttribute(
                        type="description", vals="v"
                    ),
                ),
            ],
            1,
            False,
        ),
        (
            [
                create_mock_ace(
                    ace_type=AceType.DELETE,
                    is_allow=True,
                    entity_type_id=2,
                    attribute_type_id=1,
                    attribute_type_name="cn",
                ),
                create_mock_ace(
                    ace_type=AceType.WRITE,
                    is_allow=True,
                    entity_type_id=2,
                    attribute_type_id=1,
                    attribute_type_name="description",
                ),
            ],
            [
                Changes(
                    operation=Operation.DELETE,
                    modification=PartialAttribute(type="cn", vals="value"),
                ),
                Changes(
                    operation=Operation.ADD,
                    modification=PartialAttribute(
                        type="description", vals="v"
                    ),
                ),
            ],
            1,
            False,
        ),
    ],
)
def test_check_modify_access(
    aces: list[AccessControlEntry],
    changes: list[Changes],
    entity_type_id: int,
    expected_result: bool,
) -> None:
    """Test modify access checks."""
    result = AccessManager.check_modify_access(changes, aces, entity_type_id)
    assert result == expected_result
