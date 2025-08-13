"""Common business exceptions for role service class.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class RoleError(Exception):
    """Base exception for all Role-related errors."""


class RoleNotFoundError(RoleError):
    """Raised when a role is not found in the system."""


class RoleCantModifyError(RoleError):
    """Raised when a role cannot be modified."""


class NoValidGroupsError(RoleError):
    """Raised when no valid groups are provided for a role."""


class AccessControlEntryAddError(RoleError):
    """Raised when there is an error with adding access control entries."""


class AccessControlEntryNotFoundError(RoleError):
    """Raised when an access control entry is not found."""


class NoValidDistinguishedNameError(RoleError):
    """Raised when there is an error with the base DN."""
