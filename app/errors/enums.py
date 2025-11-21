"""Errors enums."""

from enum import IntEnum, StrEnum


class ErrorCodeParts(StrEnum):
    """Error code parts."""

    AUDIT = "001"
    AUTH = "002"
    _ = "003"
    DNS = "004"
    GENERAL = "005"
    KERBEROS = "006"
    LDAP = "007"
    MFA = "008"
    NETWORK = "009"
    PASSWORD_POLICY = "010"  # NOQA S105
    ROLES = "011"


class ErrorStatusCodes(IntEnum):
    """Error status codes."""

    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    UNPROCESSABLE_ENTITY = 422
    INTERNAL_SERVER_ERROR = 500
