"""Test Container subcontainer restrictions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest

from ldap_protocol.dialogue import UserSchema
from ldap_protocol.roles.access_manager import AccessManager


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entity_type_id", "entity_type_name", "expected_result"),
    [
        (1, "Container", False),
        (3, "Organizational Unit", False),
        (2, "User", True),
        (4, "Group", True),
        (5, "Computer", True),
    ],
)
async def test_entity_creation_in_container(
    mock_regular_user: UserSchema,
    mock_ace: Mock,
    entity_type_id: int,
    entity_type_name: str,
    expected_result: bool,
) -> None:
    """Test entity creation restrictions inside Container."""
    mock_entity_type = Mock()
    mock_entity_type.id = entity_type_id
    mock_entity_type.name = entity_type_name

    result = AccessManager.check_entity_level_access(
        aces=[mock_ace],
        entity_type_id=mock_entity_type.id,
        entity_type_name=mock_entity_type.name,
        user=mock_regular_user,
        parent_object_class="container",
    )

    assert result is expected_result
