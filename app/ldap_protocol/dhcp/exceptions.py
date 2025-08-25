"""Exceptions for DHCP manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""


class DHCPError(Exception):
    """DHCP base exception."""


class DHCPAPIError(DHCPError):
    """DHCP API error."""


class DHCPConnectionError(ConnectionError):
    """DHCP connection error."""


class DHCPEntryAddError(DHCPError):
    """DHCP entry addition error."""


class DHCPEntryNotFoundError(DHCPError):
    """DHCP entry not found error."""


class DHCPEntryUpdateError(DHCPError):
    """DHCP entry update error."""
