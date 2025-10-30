"""LDAP error codes utilities.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_error_codes_mapping import get_error_code_from_ldap_code

from ldap_protocol.ldap_codes import LDAPCodes


def format_ldap_error_message(
    ldap_code: LDAPCodes,
    additional_info: str = "",
) -> str:
    """Format LDAP error message with internal error code.

    Format: "InternalCode: AdditionalInfo"
    InternalCode is extracted from ErrorCode enum mapped from LDAP code.

    :param ldap_code: LDAP protocol code
    :param additional_info: Additional error information
    :return: Formatted error message
    """
    error_code = get_error_code_from_ldap_code(ldap_code)

    if additional_info:
        return f"{error_code.value}: {additional_info}"

    return f"{error_code.value}"
