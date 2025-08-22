"""Stub DHCP manager .

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv4Network
from typing import NoReturn

from .base import AbstractDHCPManager
from .utils import logger_wraps


class StubDHCPManager(AbstractDHCPManager):
    """Stub DHCP manager class."""

    @logger_wraps(is_stub=True)
    async def create_subnet(
        self,
        name: str,
        subnet: IPv4Network,
        pool: IPv4Network | str,
        default_gateway: str | None = None,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_subnet(self, name: str) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_subnets(
        self,
    ) -> NoReturn: ...

    @logger_wraps(is_stub=True)
    async def update_subnet(
        self,
        name: str,
        subnet: IPv4Network,
        pool: IPv4Network | str,
        default_gateway: str | None = None,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def create_lease(
        self,
        mac_address: str,
        ip_address: IPv4Address,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def release_lease(self, ip_address: IPv4Address) -> None: ...

    @logger_wraps(is_stub=True)
    async def list_active_leases(
        self,
        subnet: IPv4Network,
    ) -> NoReturn: ...

    @logger_wraps(is_stub=True)
    async def find_lease(
        self,
        mac_address: str | None = None,
        hostname: str | None = None,
    ) -> NoReturn: ...

    @logger_wraps(is_stub=True)
    async def add_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address | None = None,
        hostname: str | None = None,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_reservations(
        self,
        subnet: IPv4Network,
    ) -> NoReturn: ...
