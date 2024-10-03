import functools
from enum import Enum, StrEnum

import dns
import dns.asyncquery
import dns.update
import httpx
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import CatalogueSetting

DNS_MANAGER_STATE_NAME = "DNSManagerState"
DNS_MANAGER_ZONE_NAME = "DNSManagerZoneName"
DNS_MANAGER_IP_ADDRESS_NAME = "DNSManagerIpAddress"
DNS_MANAGER_TSIG_KEY_NAME = "DNSManagerTSIGKey"


class DNSAPIError(Exception):
    """API Error."""


class DNSRecordType(str, Enum):
    """DNS record types."""
    a = "A"
    aaaa = "AAAA"
    cname = "CNAME"
    mx = "MX"
    ns = "NS"
    txt = "TXT"
    soa = "SOA"
    ptr = "PTR"
    srv = "SRV"


class DNSManagerSettings:
    """DNS Manager settings."""
    zone_name: str
    domain: str
    dns_server_ip: str
    tsig_key: str

    def __init__(self, zone_name: str, dns_server_ip: str, tsig_key: str):
        """Set settings."""
        self.zone_name = zone_name
        self.domain = zone_name + "."
        self.dns_server_ip = dns_server_ip
        self.tsig_key = tsig_key


class DNSManagerState(StrEnum):
    """DNSManager state enum."""
    NOT_CONFIGURED = '0'
    SELFHOSTED = '1'
    HOSTED = '2'


class DNSManager:
    """DNS server manager."""
    settings: DNSManagerSettings
    client: [functools.partial]
    http_client: httpx.AsyncClient

    def __init__(
        self,
        settings: DNSManagerSettings,
        http_client: httpx.AsyncClient,
    ) -> None:
        """Set up DNS manager."""
        self._settings = settings
        self.client = functools.partial(
            dns.asyncquery.tcp, where=settings.dns_server_ip,
        )
        self.http_client = http_client

    async def create_record(self, hostname, ip, record_type, ttl):
        """Create DNS record."""
        action = dns.update.Update(self._settings.zone_name)
        action.add(hostname, ttl, record_type, ip)

        await self.client(action)

    async def get_all_records(self) -> list:
        """Get all DNS records."""
        zone = dns.zone.from_xfr(
            dns.query.xfr(
                self._settings.dns_server_ip, self._settings.domain
            )
        )

        result = {}
        for name, ttl, rdata in zone.iterate_rdatas():
            if rdata.rdtype.name in result.keys():
                result[rdata.rdtype.name].append({
                    "hostname":
                        name.to_text() + f".{self._settings.zone_name}",
                    "ip": rdata.to_text(),
                    "ttl": ttl,
                })
            else:
                if rdata.rdtype.name == "SOA":
                    continue
                else:
                    result[rdata.rdtype.name] = [{
                        "hostname":
                            name.to_text() + f".{self._settings.zone_name}",
                        "ip": rdata.to_text(),
                        "ttl": ttl,
                    }]

        response = []
        for record_type in result.keys():
            response.append({
                "record_type": record_type,
                "records": result[record_type]
            })

        return response

    async def update_record(self, hostname, ip, record_type, ttl):
        """Update DNS record."""
        action = dns.update.Update(self._settings.zone_name)
        action.replace(hostname, ttl, record_type, ip)

        await self.client(action)

    async def delete_record(self, hostname, ip, record_type):
        """Delete DNS record."""
        action = dns.update.Update(self._settings.zone_name)
        action.delete(hostname, record_type, ip)

        await self.client(action)

    async def setup(
            self,
            session: AsyncSession,
            domain: str,
            dns_ip_address: str | None,
            zone_file: str | None,
            tsig_key: str | None,
    ):
        """Set up DNS server and DNS manager."""
        if tsig_key is None:
            response = await self.http_client.post("/setup/zone_file", json={
                "zone_file": zone_file.encode().hex()
            })
            if response.status_code != 200:
                raise DNSAPIError(response.text)

            response = await self.http_client.get("/setup/tsig_key")
            if response.status_code != 200:
                raise DNSAPIError(response.text)

            tsig_key = response.json()

            response = await self.http_client.get("/setup/finish")
            if response.status_code != 200:
                raise DNSAPIError(response.text)

        session.add_all(
            [
                CatalogueSetting(
                    name=DNS_MANAGER_IP_ADDRESS_NAME,
                    value=dns_ip_address,
                ),
                CatalogueSetting(
                    name=DNS_MANAGER_ZONE_NAME,
                    value=domain,
                ),
                CatalogueSetting(
                    name=DNS_MANAGER_TSIG_KEY_NAME,
                    value=tsig_key,
                ),
            ],
        )


async def get_dns_state(
    session: AsyncSession
) -> 'DNSManagerState':
    """Get or create DNS manager state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == DNS_MANAGER_STATE_NAME)
    )

    if state is None:
        session.add(
            CatalogueSetting(
                name=DNS_MANAGER_STATE_NAME,
                value=DNSManagerState.NOT_CONFIGURED,
            ),
        )
        await session.commit()
        return DNSManagerState.NOT_CONFIGURED

    return state.value


async def set_dns_manager_state(
    session: AsyncSession,
    state: 'DNSManagerState'
) -> None:
    """Update DNS state."""
    await session.execute(
        update(CatalogueSetting)
        .values({"value": state})
        .where(CatalogueSetting.name == DNS_MANAGER_STATE_NAME),
    )


async def get_dns_manager_settings(session: AsyncSession) -> dict:
    """Get DNS manager's settings."""
    settings = dict()
    for setting in await session.scalars(
            select(CatalogueSetting)
            .filter(or_(
                [
                    CatalogueSetting.name == DNS_MANAGER_ZONE_NAME,
                    CatalogueSetting.name == DNS_MANAGER_IP_ADDRESS_NAME,
                    CatalogueSetting.name == DNS_MANAGER_TSIG_KEY_NAME,
                ]
            ))
    ):
        settings[setting.name] = setting.value

    return settings


async def get_dns_manager(
    settings: DNSManagerSettings,
    http_client: httpx.AsyncClient,
) -> 'DNSManager':
    """Get DNS manager."""
    return DNSManager(
        settings=settings,
        http_client=http_client,
    )
