"""Role enums.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum


class AceType(IntEnum):
    """ACE types."""

    RIGHT_CREATE_CHILD = 0
    RIGHT_READ_PROP = 1
    RIGHT_WRITE_PROP = 2
    RIGHT_DELETE_PROP = 3
    RIGHT_PASSWORD_MODIFY = 4


class RoleScope(IntEnum):
    """Scope of the role."""

    SELF = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2
