"""Exceptions for LDAP Schema operations.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class AttributeTypeError(Exception):
    """Raised when an attribute type is not found."""


class AttributeTypeNotFoundError(AttributeTypeError):
    """Raised when an attribute type is not found."""


class AttributeTypeCantModifyError(AttributeTypeError):
    """Raised when an attribute type cannot be modified."""


class AttributeTypeAlreadyExistsError(AttributeTypeError):
    """Raised when an attribute type already exists."""


class ObjectClassTypeError(Exception):
    """Raised when an object class type is not found."""


class ObjectClassNotFoundError(ObjectClassTypeError):
    """Raised when an object class is not found."""


class ObjectClassCantModifyError(ObjectClassTypeError):
    """Raised when an object class cannot be modified."""


class ObjectClassAlreadyExistsError(ObjectClassTypeError):
    """Raised when an object class already exists."""


class EntityTypeTypeError(Exception):
    """Raised when an entity type is not found."""


class EntityTypeNotFoundError(EntityTypeTypeError):
    """Raised when an entity type is not found."""


class EntityTypeCantModifyError(EntityTypeTypeError):
    """Raised when an entity type cannot be modified."""


class EntityTypeAlreadyExistsError(EntityTypeTypeError):
    """Raised when an entity type already exists."""
