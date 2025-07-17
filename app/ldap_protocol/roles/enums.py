"""Role enums.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum


class AceType(IntEnum):
    """ACE types."""

    CREATE_CHILD = 0
    READ = 1
    WRITE = 2
    DELETE = 3
    PASSWORD_MODIFY = 4


class RoleScope(IntEnum):
    """Scope of the role."""

    SELF = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2
