"""DHCP schemas.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel, field_serializer

from ldap_protocol.dhcp.enums import DHCPManagerState


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


class DHCPLeaseToReservationErrorResponse(BaseModel):
    """Schema for responding with lease to reservation operation error."""

    text: str
    ip_address: IPv4Address | None = None
    mac_address: str | None = None


class DHCPChangeStateSchemaRequest(BaseModel):
    """Schema for setting up the DHCP server."""

    dhcp_manager_state: DHCPManagerState


class DHCPStateSchemaResponse(BaseModel):
    """Schema for responding with DHCP server state."""

    dhcp_manager_state: DHCPManagerState
