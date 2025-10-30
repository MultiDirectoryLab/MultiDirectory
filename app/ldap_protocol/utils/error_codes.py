"""LDAP error codes utilities.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enums import ErrorCode


def format_ldap_error_message(
    code: ErrorCode,
    additional_info: str = "",
) -> str:
    """Format LDAP error message with internal ErrorCode.

    Format: "<InternalCode>: <AdditionalInfo>".
    """
    if additional_info:
        return f"{code.value}: {additional_info}"
    return f"{code.value}"
