"""DNSManager: Class for encapsulating DNS business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from api.utils.exceptions import DNSError
from config import Settings
from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSRecords,
    get_dns_manager_settings,
    resolve_dns_server_ip,
)


class DNSManager:
    """Encapsulates business logic related to DNS configuration and management.

    Uses AbstractDNSManager from ldap_protocol for low-level operations.
    """

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        """Initialize dependencies of the manager (via DI).

        :param session: SQLAlchemy AsyncSession
        :param settings: Settings
        """
        self.session = session
        self.settings = settings
        self._core_manager: AbstractDNSManager | None = None

    async def _get_core_manager(self) -> AbstractDNSManager:
        """Get an instance of AbstractDNSManager with up-to-date settings.

        :return: AbstractDNSManager.
        """
        dns_settings = await get_dns_manager_settings(
            self.session, resolve_dns_server_ip(self.settings.DNS_BIND_HOST)
        )
        if (
            self._core_manager is None
            or self._core_manager._dns_settings != dns_settings
        ):
            self._core_manager = AbstractDNSManager(dns_settings)
        return self._core_manager

    async def setup(
        self,
        domain: str,
        dns_ip_address: str | None,
        zone_file: str | None,
        tsig_key: str | None,
        named_conf_local_part: str | None,
    ) -> None:
        """Create a zone, get a TSIG key, restart the DNS server.

        :param domain: domain name
        :param dns_ip_address: DNS server IP
        :param zone_file: zone file content (or None)
        :param tsig_key: TSIG key
        :param named_conf_local_part: part of named.conf config (or None)
        :raises DNSError: if setup fails.
        """
        try:
            core = await self._get_core_manager()
            await core.setup(
                self.session,
                self.settings,
                domain,
                dns_ip_address,
                zone_file,
                tsig_key,
                named_conf_local_part,
            )
        except Exception as exc:
            raise DNSError(f"DNS setup failed: {exc}")

    async def create_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int | None = None,
    ) -> None:
        """Create a DNS record.

        :param hostname: host name
        :param ip: IP address
        :param record_type: record type (A, AAAA, CNAME, etc.)
        :param ttl: record lifetime
        :raises DNSError: if creation fails.
        """
        try:
            core = await self._get_core_manager()
            await core.create_record(hostname, ip, record_type, ttl)
        except Exception as exc:
            raise DNSError(f"DNS record creation failed: {exc}")

    async def update_record(
        self,
        hostname: str,
        ip: str | None,
        record_type: str,
        ttl: int | None = None,
    ) -> None:
        """Update a DNS record.

        :param hostname: host name
        :param ip: IP address (or None)
        :param record_type: record type
        :param ttl: record lifetime
        :raises DNSError: if update fails.
        """
        try:
            core = await self._get_core_manager()
            await core.update_record(hostname, ip, record_type, ttl)
        except Exception as exc:
            raise DNSError(f"DNS record update failed: {exc}")

    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
    ) -> None:
        """Delete a DNS record.

        :param hostname: host name
        :param ip: IP address
        :param record_type: record type
        :raises DNSError: if deletion fails.
        """
        try:
            core = await self._get_core_manager()
            await core.delete_record(hostname, ip, record_type)
        except Exception as exc:
            raise DNSError(f"DNS record deletion failed: {exc}")

    async def get_all_records(self) -> list[DNSRecords]:
        """Get all DNS records.

        :return: list of grouped DNSRecords
        :raises DNSError: if retrieval fails.
        """
        try:
            core = await self._get_core_manager()
            return await core.get_all_records()
        except Exception as exc:
            raise DNSError(f"DNS record retrieval failed: {exc}")
