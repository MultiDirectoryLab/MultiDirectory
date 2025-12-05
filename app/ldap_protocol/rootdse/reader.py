"""RootDSE interactor.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import defaultdict

from config import Settings
from constants import DEFAULT_DC_POSTFIX, UNC_PREFIX
from ldap_protocol.utils.helpers import get_generalized_now

from .dto import DomainControllerInfo
from .gw_protocol import DomainReadProtocol


class RootDSEReader:
    def __init__(self, settings: Settings, gw: DomainReadProtocol) -> None:
        self._settings = settings
        self._gw = gw

    async def get(
        self,
        requested_attrs: list[str],
    ) -> defaultdict[str, list[str]]:
        domain = await self._gw.get_domain()
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


class DCInfoReader:
    def __init__(self, settings: Settings, gw: DomainReadProtocol) -> None:
        self._settings = settings
        self._gw = gw

    async def get(self) -> DomainControllerInfo:
        domain = await self._gw.get_domain()
        dns = domain.name.lower()
        nb_domain = dns.split(".")[0].upper()

        return DomainControllerInfo(
            net_bios_domain=nb_domain,
            net_bios_hostname=nb_domain + DEFAULT_DC_POSTFIX,
            unc=UNC_PREFIX + dns,
            dns=dns,
            dns_forest=dns,
            object_sid=domain.object_sid,
            object_guid=str(domain.object_guid),
        )
