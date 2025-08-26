"""Schemas for DHCP manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from .enums import KeaDHCPCommands


@dataclass
class KeaDHCPAPIRequest:
    """Base request for Kea DHCP API."""

    command: KeaDHCPCommands
    arguments: dict | None = None
