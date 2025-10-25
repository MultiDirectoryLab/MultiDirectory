"""DNS gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select, update
from sqlalchemy.engine.result import ScalarResult
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_dao import AbstractService
from entities import CatalogueSetting
from ldap_protocol.dns.base import (
    DNS_MANAGER_IP_ADDRESS_NAME,
    DNS_MANAGER_STATE_NAME,
    DNS_MANAGER_TSIG_KEY_NAME,
    DNS_MANAGER_ZONE_NAME,
    DNSManagerState,
)
from repo.pg.tables import queryable_attr as qa


class DNSGateway(AbstractService):
    """DNS gateway."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize DNS gateway."""
        self._session = session

    async def setup_dns(
        self,
        state: DNSManagerState | str,
    ) -> None:
        """Set up DNS server and DNS manager."""
        await self._session.execute(
            update(CatalogueSetting)
            .values({"value": state})
            .filter_by(name=DNS_MANAGER_STATE_NAME),
        )

    async def get_by_name(self, name: str) -> CatalogueSetting | None:
        """Get DNS by name."""
        return await self._session.scalar(
            select(CatalogueSetting).filter_by(name=name),
        )

    async def create(self, data: CatalogueSetting) -> None:
        """Create DNS."""
        self._session.add(data)
        await self._session.commit()

    async def get_dns_managers(self) -> ScalarResult[CatalogueSetting]:
        """Get DNS managers."""
        return await self._session.scalars(
            select(CatalogueSetting).filter(
                qa(CatalogueSetting.name).in_(
                    [
                        DNS_MANAGER_ZONE_NAME,
                        DNS_MANAGER_IP_ADDRESS_NAME,
                        DNS_MANAGER_TSIG_KEY_NAME,
                    ],
                ),
            ),
        )
