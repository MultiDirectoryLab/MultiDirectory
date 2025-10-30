"""LDAP error codes to internal error codes mapping.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enums import ErrorCode
from ldap_protocol.ldap_codes import LDAPCodes

LDAP_TO_ERROR_CODE_MAP: dict[LDAPCodes, ErrorCode] = {
    LDAPCodes.SUCCESS: ErrorCode.BAD_REQUEST,
    LDAPCodes.OPERATIONS_ERROR: ErrorCode.UNHANDLED_ERROR,
    LDAPCodes.PROTOCOL_ERROR: ErrorCode.BAD_REQUEST,
    LDAPCodes.UNAVAILABLE: ErrorCode.DATABASE_ERROR,
    LDAPCodes.BUSY: ErrorCode.DATABASE_ERROR,
    LDAPCodes.INVALID_CREDENTIALS: ErrorCode.INVALID_CREDENTIALS,
    LDAPCodes.INAPPROPRIATE_AUTHENTICATION: ErrorCode.UNAUTHORIZED,
    LDAPCodes.AUTH_METHOD_NOT_SUPPORTED: ErrorCode.UNAUTHORIZED,
    LDAPCodes.STRONGER_AUTH_REQUIRED: ErrorCode.UNAUTHORIZED,
    LDAPCodes.NO_SUCH_OBJECT: ErrorCode.ENTITY_NOT_FOUND,
    LDAPCodes.ENTRY_ALREADY_EXISTS: ErrorCode.ENTITY_ALREADY_EXISTS,
    LDAPCodes.NO_SUCH_ATTRIBUTE: ErrorCode.ENTITY_NOT_FOUND,
    LDAPCodes.ATTRIBUTE_OR_VALUE_EXISTS: ErrorCode.ENTITY_ALREADY_EXISTS,
    LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS: ErrorCode.PERMISSION_DENIED,
    LDAPCodes.UNWILLING_TO_PERFORM: ErrorCode.PERMISSION_DENIED,
    LDAPCodes.NOT_ALLOWED_ON_NON_LEAF: ErrorCode.PERMISSION_DENIED,
    LDAPCodes.NOT_ALLOWED_ON_RDN: ErrorCode.PERMISSION_DENIED,
    LDAPCodes.OBJECT_CLASS_MODS_PROHIBITED: ErrorCode.PERMISSION_DENIED,
    LDAPCodes.INVALID_DN_SYNTAX: ErrorCode.INVALID_INPUT,
    LDAPCodes.INVALID_ATTRIBUTE_SYNTAX: ErrorCode.INVALID_INPUT,
    LDAPCodes.OBJECT_CLASS_VIOLATION: ErrorCode.INVALID_INPUT,
    LDAPCodes.CONSTRAINT_VIOLATION: ErrorCode.VALIDATION_ERROR,
    LDAPCodes.NAMING_VIOLATION: ErrorCode.INVALID_OPERATION,
}


def get_error_code_from_ldap_code(ldap_code: LDAPCodes) -> ErrorCode:
    """Get internal error code from LDAP code.

    :param ldap_code: LDAP protocol code
    :return: Internal error code
    """
    return LDAP_TO_ERROR_CODE_MAP.get(ldap_code, ErrorCode.UNHANDLED_ERROR)
