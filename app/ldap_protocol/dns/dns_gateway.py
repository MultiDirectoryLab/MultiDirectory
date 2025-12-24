"""DNS gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Awaitable

from sqlalchemy import case, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from entities import CatalogueSetting
from ldap_protocol.dns.base import (
    DNS_MANAGER_IP_ADDRESS_NAME,
    DNS_MANAGER_STATE_NAME,
    DNS_MANAGER_TSIG_KEY_NAME,
    DNS_MANAGER_ZONE_NAME,
    DNSManagerSettings,
)
from ldap_protocol.dns.dto import DNSSettingsDTO
from repo.pg.tables import queryable_attr as qa

from .enums import DNSManagerState


class DNSStateGateway:
    """DNS gateway."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize DNS gateway."""
        self._session = session

    async def get(self, name: str) -> CatalogueSetting | None:
        """Get DNS by name."""
        return await self._session.scalar(
            select(CatalogueSetting)
            .filter_by(name=name),
        )

    async def create(self, data: CatalogueSetting) -> None:
        """Create DNS."""
        self._session.add(data)
        await self._session.commit()

    async def get_dns_settings(self) -> dict[str, str]:
        """Get DNS managers."""
        return {
            setting.name: setting.value
            for setting in await self._session.scalars(
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
        }

    async def update_settings(
        self,
        data: DNSSettingsDTO,
    ) -> None:
        """Update DNS settings."""
        settings = [
            (
                qa(CatalogueSetting.name) == DNS_MANAGER_ZONE_NAME,
                data.domain,
            ),
            (
                qa(CatalogueSetting.name) == DNS_MANAGER_IP_ADDRESS_NAME,
                str(data.dns_server_ip),
            ),
            (
                qa(CatalogueSetting.name) == DNS_MANAGER_TSIG_KEY_NAME,
                data.tsig_key,
            ),
        ]

        await self._session.execute(
            update(CatalogueSetting)
            .where(
                qa(CatalogueSetting.name).in_(
                    [
                        DNS_MANAGER_ZONE_NAME,
                        DNS_MANAGER_IP_ADDRESS_NAME,
                        DNS_MANAGER_TSIG_KEY_NAME,
                    ],
                ),
            )
            .values(
                {
                    "value": case(
                        *settings,
                        else_=qa(CatalogueSetting.value),
                    ),
                },
            ),
        )

    async def create_settings(
        self,
        data: DNSSettingsDTO,
    ) -> None:
        """Create DNS settings."""
        self._session.add_all(
            [
                CatalogueSetting(
                    name=DNS_MANAGER_ZONE_NAME,
                    value=data.domain or "",
                ),
                CatalogueSetting(
                    name=DNS_MANAGER_IP_ADDRESS_NAME,
                    value=str(data.dns_server_ip),
                ),
                CatalogueSetting(
                    name=DNS_MANAGER_TSIG_KEY_NAME,
                    value=data.tsig_key or "",
                ),
            ],
        )
        await self._session.flush()

    async def get_dns_manager_settings(
        self,
        resolve_coro: Awaitable[str],
    ) -> DNSManagerSettings:
        """Get DNS manager settings."""
        settings = await self.get_dns_settings()
        dns_server_ip = settings.get(DNS_MANAGER_IP_ADDRESS_NAME)

        if await self.get_dns_state() == DNSManagerState.SELFHOSTED:
            dns_server_ip = await resolve_coro

        return DNSManagerSettings(
            zone_name=settings.get(DNS_MANAGER_ZONE_NAME),
            dns_server_ip=dns_server_ip,
            tsig_key=settings.get(DNS_MANAGER_TSIG_KEY_NAME),
        )

    async def get_dns_state(self) -> DNSManagerState:
        """Get DNS state."""
        state = await self.get(DNS_MANAGER_STATE_NAME)
        if state is None:
            await self.create(
                CatalogueSetting(
                    name=DNS_MANAGER_STATE_NAME,
                    value=DNSManagerState.NOT_CONFIGURED,
                ),
            )
            return DNSManagerState.NOT_CONFIGURED
        return DNSManagerState(state.value)

    async def set_state(
        self,
        state: DNSManagerState,
    ) -> None:
        """Set DNS state."""
        existing_state = await self.get(DNS_MANAGER_STATE_NAME)
        if existing_state is None:
            await self.create(
                CatalogueSetting(
                    name=DNS_MANAGER_STATE_NAME,
                    value=state,
                ),
            )
        else:
            await self._session.execute(
                update(CatalogueSetting)
                .values({"value": state})
                .filter_by(name=DNS_MANAGER_STATE_NAME),
            )

    async def get_state(self) -> DNSManagerState:
        """Get DNS state."""
        state = await self.get(DNS_MANAGER_STATE_NAME)
        if state is None:
            return DNSManagerState.NOT_CONFIGURED
        return DNSManagerState(state.value)
