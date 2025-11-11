"""Exceptions for DHCP manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class DHCPError(Exception):
    """DHCP base exception."""


class DHCPAPIError(DHCPError):
    """DHCP API error."""


class DHCPValidatonError(DHCPError):
    """DHCP validation error."""


class DHCPConnectionError(ConnectionError):
    """DHCP connection error."""


class DHCPOperationError(DHCPError):
    """DHCP operation error."""


class DHCPEntryAddError(DHCPError):
    """DHCP entry addition error."""


class DHCPEntryNotFoundError(DHCPError):
    """DHCP entry not found error."""


class DHCPEntryDeleteError(DHCPError):
    """DHCP entry deletion error."""


class DHCPEntryUpdateError(DHCPError):
    """DHCP entry update error."""


class DHCPConflictError(DHCPError):
    """DHCP conflict error."""


class DHCPUnsupportedError(DHCPError):
    """DHCP unsupported error."""
