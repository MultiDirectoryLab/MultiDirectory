"""RootDSE interactor.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import defaultdict

from config import Settings
from constants import DEFAULT_DC_POSTFIX, UNC_PREFIX
from enums import SidPrefix
from ldap_protocol.rid_manager import ObjectSIDUseCase
from ldap_protocol.utils.helpers import get_generalized_now

from .dto import DomainControllerInfo
from .gw_protocol import DomainReadProtocol


class RootDSEReader:
    def __init__(self, settings: Settings, gw: DomainReadProtocol) -> None:
        self._settings = settings
        self._gw = gw

    async def get(
        self,
        requested_attrs: set[str],
    ) -> defaultdict[str, list[str]]:
        domain = await self._gw.get_domain()
        schema = "CN=Schema"

        all_attrs: dict[str, list[str]] = {
            "dnsHostName": [domain.name],
            "serverName": [domain.name],
            "serviceName": [domain.name],
            "dsServiceName": [domain.name],
            "LDAPServiceName": [domain.name],
            "dnsForestName": [domain.name],
            "dnsDomainName": [domain.name],
            "domainGuid": [str(domain.object_guid)],
            "vendorName": [self._settings.VENDOR_NAME],
            "vendorVersion": [self._settings.VENDOR_VERSION],
            "namingContexts": [domain.path_dn, schema],
            "rootDomainNamingContext": [domain.path_dn],
            "supportedLDAPVersion": ["3"],
            "defaultNamingContext": [domain.path_dn],
            "currentTime": [
                get_generalized_now(self._settings.TIMEZONE),
            ],
            "subschemaSubentry": [schema],
            "schemaNamingContext": [schema],
            "supportedSASLMechanisms": [
                "ANONYMOUS",
                "PLAIN",
                "GSSAPI",
                "GSS-SPNEGO",
            ],
            "highestCommittedUSN": ["126991"],
            "supportedExtension": [
                "1.3.6.1.4.1.4203.1.11.3",  # whoami
                "1.3.6.1.4.1.4203.1.11.1",  # password modify
            ],
            "supportedControl": [
                "2.16.840.1.113730.3.4.4",  # password expire policy
            ],
            "domainFunctionality": ["7"],
            "forestFunctionality": ["7"],
            "supportedLDAPPolicies": [
                "MaxConnIdleTime",
                "MaxPageSize",
                "MaxValRange",
            ],
            "supportedCapabilities": [
                "1.2.840.113556.1.4.800",  # ACTIVE_DIRECTORY_OID
                "1.2.840.113556.1.4.1670",  # ACTIVE_DIRECTORY_V51_OID
                "1.2.840.113556.1.4.1791",  # ACTIVE_DIRECTORY_LDAP_INTEG_OID
            ],
        }

        if not requested_attrs or "*" in requested_attrs:
            return defaultdict(list, all_attrs)

        result = defaultdict(list)

        for attr_name, values in all_attrs.items():
            if attr_name.lower() in requested_attrs:
                result[attr_name].extend(values)

        return result


class DCInfoReader:
    def __init__(
        self,
        settings: Settings,
        gw: DomainReadProtocol,
        object_sid_use_case: ObjectSIDUseCase,
    ) -> None:
        self._settings = settings
        self._gw = gw
        self._object_sid_use_case = object_sid_use_case

    async def get(self) -> DomainControllerInfo:
        domain = await self._gw.get_domain()
        dns = domain.name.lower()
        nb_domain = dns.split(".")[0].upper()
        domain_identifier = (
            await self._object_sid_use_case.get_domain_identifier()
        )

        return DomainControllerInfo(
            net_bios_domain=nb_domain,
            net_bios_hostname=nb_domain + DEFAULT_DC_POSTFIX,
            unc=UNC_PREFIX + dns,
            dns=dns,
            dns_forest=dns,
            object_sid=f"{SidPrefix.DOMAIN_IDENTIFIER}-{domain_identifier}",
            object_guid=str(domain.object_guid),
        )
