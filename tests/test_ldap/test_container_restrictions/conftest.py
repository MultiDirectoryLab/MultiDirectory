"""Conftest for Container restrictions tests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest_asyncio

from entities import AccessControlEntry
from ldap_protocol.dialogue import UserSchema


def create_mock_ace(
    is_allow: bool = True,
    entity_type_id: int | None = None,
) -> AccessControlEntry:
    """Create a mock AccessControlEntry for testing."""
    ace = Mock(spec=AccessControlEntry)
    ace.is_allow = is_allow
    ace.entity_type_id = entity_type_id
    return ace


@pytest_asyncio.fixture
async def mock_regular_user() -> UserSchema:
    """Create a mock regular user."""
    user = Mock(spec=UserSchema)
    user.is_system_user = False
    user.role_ids = [1]
    return user
