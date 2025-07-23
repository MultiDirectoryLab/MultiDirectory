"""Conftest for AccessManager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

from enums import AceType

from models import AccessControlEntry


def create_mock_ace(
    ace_type: AceType = AceType.READ,
    is_allow: bool = True,
    attribute_type_id: int | None = None,
    attribute_type_name: str | None = None,
    entity_type_id: int | None = None,
) -> AccessControlEntry:
    """Create a mock AccessControlEntry for testing."""
    ace = Mock(spec=AccessControlEntry)
    ace.ace_type = ace_type
    ace.is_allow = is_allow
    ace.attribute_type_id = attribute_type_id
    ace.attribute_type_name = attribute_type_name
    ace.entity_type_id = entity_type_id
    return ace
