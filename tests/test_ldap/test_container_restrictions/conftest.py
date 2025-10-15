"""Conftest for Container restrictions tests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest_asyncio

from entities import AccessControlEntry
from ldap_protocol.dialogue import UserSchema


@pytest_asyncio.fixture
def mock_ace() -> Mock:
    """Create a mock AccessControlEntry factory for testing."""
    ace = Mock(spec=AccessControlEntry)
    ace.is_allow = True
    ace.entity_type_id = None
    return ace


@pytest_asyncio.fixture
async def mock_regular_user() -> UserSchema:
    """Create a mock regular user."""
    user = Mock(spec=UserSchema)
    user.is_system_user = False
    user.role_ids = [1]
    return user
