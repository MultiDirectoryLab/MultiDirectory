"""DNS exceptions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class DNSError(Exception):
    """DNS Error."""


class DNSSetupError(DNSError):
    """DNS setup error."""


class DNSRecordCreateError(DNSError):
    """DNS record create error."""


class DNSRecordUpdateError(DNSError):
    """DNS record update error."""


class DNSRecordDeleteError(DNSError):
    """DNS record delete error."""


class DNSZoneCreateError(DNSError):
    """DNS zone create error."""


class DNSZoneUpdateError(DNSError):
    """DNS zone update error."""


class DNSZoneDeleteError(DNSError):
    """DNS zone delete error."""


class DNSUpdateServerOptionsError(DNSError):
    """DNS update server options error."""
