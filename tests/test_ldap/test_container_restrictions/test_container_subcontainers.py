"""Test Container subcontainer restrictions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest

from ldap_protocol.dialogue import UserSchema
from ldap_protocol.roles.access_manager import AccessManager

from .conftest import create_mock_ace


@pytest.mark.asyncio
async def test_container_creation_in_container_denied(
    mock_regular_user: UserSchema,
) -> None:
    """Test that Container cannot be created inside another Container."""
    mock_aces = [create_mock_ace(is_allow=True, entity_type_id=None)]

    mock_entity_type = Mock()
    mock_entity_type.id = 1
    mock_entity_type.name = "Container"

    result = AccessManager.check_entity_level_access(
        aces=mock_aces,
        entity_type_id=mock_entity_type.id,
        entity_type_name=mock_entity_type.name,
        user=mock_regular_user,
        parent_object_class="container",
    )

    assert result is False


@pytest.mark.asyncio
async def test_ou_creation_in_container_denied(
    mock_regular_user: UserSchema,
) -> None:
    """Test that Organizational Unit cannot be created inside Container."""
    mock_aces = [create_mock_ace(is_allow=True, entity_type_id=None)]

    mock_entity_type = Mock()
    mock_entity_type.id = 3
    mock_entity_type.name = "Organizational Unit"

    result = AccessManager.check_entity_level_access(
        aces=mock_aces,
        entity_type_id=mock_entity_type.id,
        entity_type_name=mock_entity_type.name,
        user=mock_regular_user,
        parent_object_class="container",
    )

    assert result is False


@pytest.mark.asyncio
async def test_user_creation_in_container_allowed(
    mock_regular_user: UserSchema,
) -> None:
    """Test that User can be created inside Container."""
    mock_aces = [create_mock_ace(is_allow=True, entity_type_id=None)]

    mock_entity_type = Mock()
    mock_entity_type.id = 2
    mock_entity_type.name = "User"

    result = AccessManager.check_entity_level_access(
        aces=mock_aces,
        entity_type_id=mock_entity_type.id,
        entity_type_name=mock_entity_type.name,
        user=mock_regular_user,
        parent_object_class="container",
    )

    assert result is True


@pytest.mark.asyncio
async def test_group_creation_in_container_allowed(
    mock_regular_user: UserSchema,
) -> None:
    """Test that Group can be created inside Container."""
    mock_aces = [create_mock_ace(is_allow=True, entity_type_id=None)]

    mock_entity_type = Mock()
    mock_entity_type.id = 4
    mock_entity_type.name = "Group"

    result = AccessManager.check_entity_level_access(
        aces=mock_aces,
        entity_type_id=mock_entity_type.id,
        entity_type_name=mock_entity_type.name,
        user=mock_regular_user,
        parent_object_class="container",
    )

    assert result is True


@pytest.mark.asyncio
async def test_computer_creation_in_container_allowed(
    mock_regular_user: UserSchema,
) -> None:
    """Test that Computer can be created inside Container."""
    mock_aces = [create_mock_ace(is_allow=True, entity_type_id=None)]

    mock_entity_type = Mock()
    mock_entity_type.id = 5
    mock_entity_type.name = "Computer"

    result = AccessManager.check_entity_level_access(
        aces=mock_aces,
        entity_type_id=mock_entity_type.id,
        entity_type_name=mock_entity_type.name,
        user=mock_regular_user,
        parent_object_class="container",
    )

    assert result is True
