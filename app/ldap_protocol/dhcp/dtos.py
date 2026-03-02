"""Schemas for DHCP manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field

from .dataclasses import DHCPLease, DHCPReservation, DHCPSubnet
from .enums import KeaDHCPCommands


@dataclass
class KeaDHCPCommandRequest:
    """Single command request."""

    command: KeaDHCPCommands


@dataclass
class KeaDHCPBaseAPIRequest(KeaDHCPCommandRequest):
    """Base request for Kea DHCP API."""

    arguments: list[int] | dict[str, str] | None = None
    service: list[str] = field(default_factory=lambda: ["dhcp4"])


@dataclass
class KeaDHCPAPISubnetRequest(KeaDHCPCommandRequest):
    """Request for Kea DHCP API to manage subnets."""

    subnet4: DHCPSubnet | list[DHCPSubnet]
    service: list[str] = field(default_factory=lambda: ["dhcp4"])


@dataclass
class KeaDHCPAPILeaseRequest(KeaDHCPCommandRequest):
    """Request for Kea DHCP API to manage leases."""

    lease: DHCPLease
    service: list[str] = field(default_factory=lambda: ["dhcp4"])


@dataclass
class KeaDHCPAPIReservationRequest(KeaDHCPCommandRequest):
    """Request for Kea DHCP API to manage reservations."""

    arguments: DHCPReservation
    service: list[str] = field(default_factory=lambda: ["dhcp4"])
