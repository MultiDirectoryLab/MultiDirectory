"""Exceptions for LDAP Protocol operations.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""


class InstanceNotFoundError(Exception):
    """Raised when an instance is not found."""


class InstanceCantModifyError(Exception):
    """Raised when an instance cannot be modified."""
