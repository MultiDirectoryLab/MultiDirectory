"""Exceptions for LDAP Schema operations.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException, ErrorStatusCodes


class ErrorCodes(IntEnum):
    """Error codes for LDAP Schema operations."""

    BASE_ERROR = 0
    ATTRIBUTE_TYPE_NOT_FOUND_ERROR = 1
    ATTRIBUTE_TYPE_CANT_MODIFY_ERROR = 2
    ATTRIBUTE_TYPE_ALREADY_EXISTS_ERROR = 3
    OBJECT_CLASS_NOT_FOUND_ERROR = 4
    OBJECT_CLASS_CANT_MODIFY_ERROR = 5
    OBJECT_CLASS_ALREADY_EXISTS_ERROR = 6
    ENTITY_TYPE_NOT_FOUND_ERROR = 7
    ENTITY_TYPE_CANT_MODIFY_ERROR = 8
    ENTITY_TYPE_ALREADY_EXISTS_ERROR = 9


class LdapSchemaError(BaseDomainException):
    """Raised when an LDAP Schema error occurs."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR
    status_code: ErrorStatusCodes = ErrorStatusCodes.BAD_REQUEST


class AttributeTypeNotFoundError(LdapSchemaError):
    """Raised when an attribute type is not found."""

    code = ErrorCodes.ATTRIBUTE_TYPE_NOT_FOUND_ERROR


class AttributeTypeCantModifyError(LdapSchemaError):
    """Raised when an attribute type cannot be modified."""

    code = ErrorCodes.ATTRIBUTE_TYPE_CANT_MODIFY_ERROR


class AttributeTypeAlreadyExistsError(LdapSchemaError):
    """Raised when an attribute type already exists."""

    code = ErrorCodes.ATTRIBUTE_TYPE_ALREADY_EXISTS_ERROR


class ObjectClassNotFoundError(LdapSchemaError):
    """Raised when an object class is not found."""

    code = ErrorCodes.OBJECT_CLASS_NOT_FOUND_ERROR


class ObjectClassCantModifyError(LdapSchemaError):
    """Raised when an object class cannot be modified."""

    code = ErrorCodes.OBJECT_CLASS_CANT_MODIFY_ERROR


class ObjectClassAlreadyExistsError(LdapSchemaError):
    """Raised when an object class already exists."""

    code = ErrorCodes.OBJECT_CLASS_ALREADY_EXISTS_ERROR


class EntityTypeNotFoundError(LdapSchemaError):
    """Raised when an entity type is not found."""

    code = ErrorCodes.ENTITY_TYPE_NOT_FOUND_ERROR


class EntityTypeCantModifyError(LdapSchemaError):
    """Raised when an entity type cannot be modified."""

    code = ErrorCodes.ENTITY_TYPE_CANT_MODIFY_ERROR


class EntityTypeAlreadyExistsError(LdapSchemaError):
    """Raised when an entity type already exists."""

    code = ErrorCodes.ENTITY_TYPE_ALREADY_EXISTS_ERROR
