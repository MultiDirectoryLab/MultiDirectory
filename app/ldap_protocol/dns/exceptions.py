"""DNS exceptions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, unique

from errors import BaseDomainException


@unique
class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    DNS_SETUP_ERROR = 1
    DNS_RECORD_CREATE_ERROR = 2
    DNS_RECORD_UPDATE_ERROR = 3
    DNS_RECORD_DELETE_ERROR = 4
    DNS_ZONE_CREATE_ERROR = 5
    DNS_ZONE_UPDATE_ERROR = 6
    DNS_ZONE_DELETE_ERROR = 7
    DNS_UPDATE_SERVER_OPTIONS_ERROR = 8
    DNS_CONNECTION_ERROR = 9
    DNS_NOT_IMPLEMENTED_ERROR = 10


class DNSError(BaseDomainException):
    """DNS Error."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR


class DNSSetupError(DNSError):
    """DNS setup error."""

    code = ErrorCodes.DNS_SETUP_ERROR


class DNSRecordCreateError(DNSError):
    """DNS record create error."""

    code = ErrorCodes.DNS_RECORD_CREATE_ERROR


class DNSRecordUpdateError(DNSError):
    """DNS record update error."""

    code = ErrorCodes.DNS_RECORD_UPDATE_ERROR


class DNSRecordDeleteError(DNSError):
    """DNS record delete error."""

    code = ErrorCodes.DNS_RECORD_DELETE_ERROR


class DNSZoneCreateError(DNSError):
    """DNS zone create error."""

    code = ErrorCodes.DNS_ZONE_CREATE_ERROR


class DNSZoneUpdateError(DNSError):
    """DNS zone update error."""

    code = ErrorCodes.DNS_ZONE_UPDATE_ERROR


class DNSZoneDeleteError(DNSError):
    """DNS zone delete error."""

    code = ErrorCodes.DNS_ZONE_DELETE_ERROR


class DNSUpdateServerOptionsError(DNSError):
    """DNS update server options error."""

    code = ErrorCodes.DNS_UPDATE_SERVER_OPTIONS_ERROR


class DNSConnectionError(DNSError):
    """DNS connection error."""

    code = ErrorCodes.DNS_CONNECTION_ERROR


class DNSNotImplementedError(DNSError):
    """DNS not implemented error."""

    code = ErrorCodes.DNS_NOT_IMPLEMENTED_ERROR
