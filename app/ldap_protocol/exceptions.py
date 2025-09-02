"""Exceptions for LDAP Protocol operations.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""


class AttributeTypeError(Exception):
    """Raised when an attribute type is not found."""


class InstanceNotFoundError(AttributeTypeError):
    """Raised when an instance is not found."""


class InstanceCantModifyError(AttributeTypeError):
    """Raised when an instance cannot be modified."""


class InstanceAlreadyExistsError(AttributeTypeError):
    """Raised when an instance already exists."""


class AttributeTypeNotFoundError(InstanceNotFoundError):
    """Attribute Type not found."""


class AttributeTypeCantModifyError(InstanceCantModifyError):
    """Attribute Type cannot be modified."""


class AttributeTypeAlreadyExistsError(InstanceAlreadyExistsError):
    """Attribute Type already exists."""
