"""LDAP Dataclasses for handle requests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from entities import Directory
from ldap_protocol.utils.helpers import get_generalized_now


class DomainInfo:
    """DC info dataclass."""

    net_bios_domain: str
    net_bios_hostname: str
    unc: str
    dns: str
    dns_forest: str
    object_sid: str
    object_guid: str


class RootDSEGateway:
    """RootDSE gw."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        """Setu up gw."""
        self._session = session
        self._settings = settings

    async def _query(self) -> Directory:
        domain_query = select(Directory).filter_by(object_class="domain")
        return (await self._session.scalars(domain_query)).one()

    async def get(
        self,
        requested_attrs: list[str],
    ) -> defaultdict[str, list[str]]:
        """Get RootDSE.

        :return defaultdict[str, list[str]]: queried attrs
        """
        domain = await self._query()
        data = defaultdict(list)
        schema = "CN=Schema"
        if requested_attrs == ["subschemasubentry"]:
            data["subschemaSubentry"].append(schema)
            return data

        data["dnsHostName"].append(domain.name)
        data["serverName"].append(domain.name)
        data["serviceName"].append(domain.name)
        data["dsServiceName"].append(domain.name)
        data["LDAPServiceName"].append(domain.name)
        data["dnsForestName"].append(domain.name)
        data["dnsDomainName"].append(domain.name)
        data["domainGuid"].append(str(domain.object_guid))
        data["SID"].append(domain.object_sid)
        data["vendorName"].append(self._settings.VENDOR_NAME)
        data["vendorVersion"].append(self._settings.VENDOR_VERSION)
        data["namingContexts"].append(domain.path_dn)
        data["namingContexts"].append(schema)
        data["rootDomainNamingContext"].append(domain.path_dn)
        data["supportedLDAPVersion"].append("3")
        data["defaultNamingContext"].append(domain.path_dn)
        data["currentTime"].append(
            get_generalized_now(self._settings.TIMEZONE),
        )
        data["subschemaSubentry"].append(schema)
        data["schemaNamingContext"].append(schema)
        data["supportedSASLMechanisms"] = [
            "ANONYMOUS",
            "PLAIN",
            "GSSAPI",
            "GSS-SPNEGO",
        ]
        data["highestCommittedUSN"].append("126991")
        data["supportedExtension"] = [
            "1.3.6.1.4.1.4203.1.11.3",  # whoami
            "1.3.6.1.4.1.4203.1.11.1",  # password modify
        ]
        data["supportedControl"] = [
            "2.16.840.1.113730.3.4.4",  # password expire policy
        ]
        data["domainFunctionality"].append("0")
        data["supportedLDAPPolicies"] = [
            "MaxConnIdleTime",
            "MaxPageSize",
            "MaxValRange",
        ]
        data["supportedCapabilities"] = [
            "1.2.840.113556.1.4.800",  # ACTIVE_DIRECTORY_OID
            "1.2.840.113556.1.4.1670",  # ACTIVE_DIRECTORY_V51_OID
            "1.2.840.113556.1.4.1791",  # ACTIVE_DIRECTORY_LDAP_INTEG_OID
        ]

        return data
