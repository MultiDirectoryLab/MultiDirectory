"""DNS exceptions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import StrEnum

from errors import AbstractException, ErrorStatusCodes


class ErrorCodes(StrEnum):
    """Error codes."""

    DNS_SETUP_ERROR = "01"
    DNS_RECORD_CREATE_ERROR = "02"
    DNS_RECORD_UPDATE_ERROR = "03"
    DNS_RECORD_DELETE_ERROR = "04"
    DNS_ZONE_CREATE_ERROR = "05"
    DNS_ZONE_UPDATE_ERROR = "06"
    DNS_ZONE_DELETE_ERROR = "07"
    DNS_UPDATE_SERVER_OPTIONS_ERROR = "08"


class DNSError(AbstractException):
    """DNS Error."""

    status_code = ErrorStatusCodes.BAD_REQUEST


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
