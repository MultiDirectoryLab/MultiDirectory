"""Schemas for DHCP manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel, field_serializer

from .dataclasses import DHCPLease, DHCPReservation, DHCPSubnet
from .enums import DHCPManagerState, KeaDHCPCommands


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


class DHCPSubnetSchemaAddRequest(BaseModel):
    """Schema for creating a new DHCP subnet."""

    subnet: IPv4Network
    pool: IPv4Network | str
    valid_lifetime: int | None = None
    default_gateway: IPv4Address | None = None

    @field_serializer("subnet")
    def serialize_subnet(self, subnet: IPv4Network) -> str:
        return str(subnet)

    @field_serializer("pool")
    def serialize_pool(self, pool: IPv4Network | str) -> str:
        return str(pool)

    @field_serializer("default_gateway")
    def serialize_default_gateway(
        self,
        gateway: IPv4Address | None,
    ) -> str | None:
        return str(gateway) if gateway else None


class DHCPSubnetSchemaResponse(BaseModel):
    """Schema for responding with DHCP subnet information."""

    id: int
    subnet: IPv4Network
    pool: list[IPv4Network | str]
    valid_lifetime: int | None = None
    default_gateway: IPv4Address | None = None

    @field_serializer("subnet")
    def serialize_subnet(self, subnet: IPv4Network) -> str:
        return str(subnet)

    @field_serializer("pool")
    def serialize_pool(self, pool: list[IPv4Network | str]) -> list[str]:
        return [str(p) for p in pool]

    @field_serializer("default_gateway")
    def serialize_default_gateway(
        self,
        gateway: IPv4Address | None,
    ) -> str | None:
        return str(gateway) if gateway else None


class DHCPLeaseSchemaRequest(BaseModel):
    """Schema for creating a new DHCP lease."""

    subnet_id: int
    ip_address: IPv4Address
    mac_address: str
    hostname: str | None = None
    valid_lifetime: int | None = None


class DHCPLeaseSchemaResponse(BaseModel):
    """Schema for responding with DHCP lease information."""

    subnet_id: int
    ip_address: IPv4Address
    mac_address: str
    hostname: str | None = None
    expires: datetime | None = None


class DHCPReservationSchemaRequest(BaseModel):
    """Schema for creating a new DHCP reservation."""

    subnet_id: int
    ip_address: IPv4Address
    mac_address: str
    hostname: str | None = None


class DHCPReservationSchemaResponse(BaseModel):
    """Schema for responding with DHCP reservation information."""

    subnet_id: int
    ip_address: IPv4Address
    mac_address: str
    hostname: str | None = None


class DHCPChangeStateSchemaRequest(BaseModel):
    """Schema for setting up the DHCP server."""

    dhcp_manager_state: DHCPManagerState
