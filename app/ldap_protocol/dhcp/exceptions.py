"""Exceptions for DHCP manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""
class DHCPError(Exception):
    """DHCP manager error."""


class DHCPAPIError(Exception):
    """DHCP API error."""


class DHCPConnectionError(ConnectionError):
    """DHCP connection error."""
