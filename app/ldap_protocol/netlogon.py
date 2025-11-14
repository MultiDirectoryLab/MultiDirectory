"""NetLogon attribute handler.

Docs:

https://learn.microsoft.com/en-us/openspecs/windows_protocols/


Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import ipaddress
import struct
import uuid
from collections import defaultdict
from enum import IntEnum, IntFlag
from typing import Any, Self

from ldap_protocol.asn1parser import ASN1Row


class NetLogonOPCode(IntEnum):
    """NetLogon operational codes.

    ms-adts/07133ff2-a9a3-4aa9-8896-a7dcb53bdfe9
    """

    LOGON_PRIMARY_RESPONSE = 12
    LOGON_SAM_LOGON_RESPONSE = 19
    LOGON_SAM_PAUSE_RESPONSE = 20
    LOGON_SAM_USER_UNKNOWN = 21
    LOGON_SAM_LOGON_RESPONSE_EX = 23
    LOGON_SAM_PAUSE_RESPONSE_EX = 24
    LOGON_SAM_USER_UNKNOWN_EX = 25


class DSFlag(IntFlag):
    """Domain controller flags mapping.

    ms-adts/f55d3f53-351d-4407-940e-f53eb6154af0
    """

    PDC_FLAG = 0x00000001
    GC_FLAG = 0x00000004
    LDAP_FLAG = 0x00000008
    DS_FLAG = 0x00000010
    KDC_FLAG = 0x00000020
    TIMESERV_FLAG = 0x00000040
    CLOSEST_FLAG = 0x00000080
    WRITABLE_FLAG = 0x00000100
    GOOD_TIMESERV_FLAG = 0x00000200
    NDNC_FLAG = 0x00000400
    SELECT_SECRET_DOMAIN_6_FLAG = 0x00000800
    FULL_SECRET_DOMAIN_6_FLAG = 0x00001000
    WS_FLAG = 0x00002000
    PING_FLAGS = 0x00004000
    DNS_CONTROLLER_FLAG = 0x20000000
    DNS_DOMAIN_FLAG = 0x40000000
    DNS_FOREST_FLAG = 0x80000000


class NetLogonNtVersionFlag(IntFlag):
    """Netlogon NT version flags mapping.

    ms-adts/8e6a9efa-6312-44e2-af12-06ad73afbfa5
    """

    NETLOGON_NT_VERSION_1 = 0x00000001
    NETLOGON_NT_VERSION_5 = 0x00000002
    NETLOGON_NT_VERSION_5EX = 0x00000004
    NETLOGON_NT_VERSION_5EX_WITH_IP = 0x00000008
    NETLOGON_NT_VERSION_WITH_CLOSEST_SITE = 0x00000010
    NETLOGON_NT_VERSION_AVOID_NT4EMUL = 0x01000000
    NETLOGON_NT_VERSION_PDC = 0x10000000
    NETLOGON_NT_VERSION_IP = 0x20000000
    NETLOGON_NT_VERSION_LOCAL = 0x40000000
    NETLOGON_NT_VERSION_GC = 0x80000000


class NetLogonAttributeHandler:
    """NetLogon attribute handler.

    ms-adts/895a7744-aff3-4f64-bcfa-f8c05915d2e9
    """

    dnsdomain: str | None = None
    host: str | None = None
    dnshostname: str | None = None
    user: str | None = None
    aac: int | None = None  # uac in netlogon for specific account
    domainsid: str | None = None
    domainguid: uuid.UUID | None = None
    ntver: int = 0x00000000

    def __init__(self, root_dse: defaultdict[str, list[str]]) -> None:
        """Init base info."""
        self.__info: dict[str, Any] = {}
        self.__root_dse = root_dse

    @classmethod
    def from_filter(
        cls,
        root_dse: defaultdict[str, list[str]],
        expr: ASN1Row,
    ) -> Self:
        """Parse NetLogon filter."""
        obj = cls(root_dse)
        for item in expr.value:
            attr, value = item.value

            if hasattr(obj, attr.value.lower()):
                obj.__setattr__(
                    attr.value.lower(),
                    value.value,
                )

        return obj

    def set_info(self, uac: bool) -> None:
        """Get info from filter."""
        if self.domainguid is not None:
            self.__info["domain_guid"] = self.domainguid
        else:
            self.__info["domain_guid"] = uuid.UUID(int=0)

        if self.dnsdomain is not None:
            self.__info["domain_dns"] = self.dnsdomain
        else:
            if self.__info["domain_guid"] == uuid.UUID(int=0):
                self.__info["domain_dns"] = self.__root_dse["dnsHostName"][0]
            else:
                self.__info["domain_dns"] = ""

        if self.__info["domain_guid"] == uuid.UUID(int=0):
            self.__info["nc_used"] = self.__info["domain_dns"]
        else:
            self.__info["nc_used"] = self.__info["domain_guid"]

        if self.domainsid is not None:
            self.__info["domain_sid"] = self.domainsid
        else:
            self.__info["domain_sid"] = ""

        if self.user is not None:
            self.__info["user"] = self.user
        else:
            self.__info["user"] = ""

        self.__info["has_user"] = uac

        self.__info["site"] = "Default-First-Site-Name"
        self.__info["ntver"] = self.ntver

    @staticmethod
    def _convert_little_endian_string_to_int(value: str) -> int:
        """Convert little-endian string to int."""
        return int.from_bytes(
            value.encode().decode("unicode_escape").encode(),
            byteorder="little",
            signed=False,
        )

    def get_attr(self, uac: bool) -> bytes:
        """Get NetLogon response."""
        self.set_info(uac)
        if bool(
            self._convert_little_endian_string_to_int(self.__info["ntver"])
            & NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5EX,
        ) or bool(
            self._convert_little_endian_string_to_int(self.__info["ntver"])
            & NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5EX_WITH_IP,
        ):
            return self._get_netlogon_response_5_ex()

        if bool(
            self._convert_little_endian_string_to_int(self.__info["ntver"])
            & NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5,
        ):
            return self._get_netlogon_response_5()

        return self._get_netlogon_response_nt40()

    def _pack_value(self, values: tuple) -> bytes:
        """Pack values."""
        packed_value = b""
        for value in values:
            if value[0] is None:
                continue
            if value[1] in ["utf-8", "unicode"]:
                packed_string = self._pack_string(value[0], value[1])
                if len(value[1]) > 0:
                    packed_string += struct.pack("<B", 0)
                    if packed_string in packed_value:
                        packed_value += self._get_pointer(
                            packed_string,
                            packed_value,
                        )
                    else:
                        packed_value += packed_string
            elif value[1] == "uuid":
                packed_value += value[0].bytes_le
            elif value[1] is None:
                packed_value += value[0]
            else:
                packed_value += struct.pack(value[1], value[0])

        return packed_value

    @staticmethod
    def _get_pointer(packed_string: bytes, packed_value: bytes) -> bytes:
        """Get pointer, reference RFC 1035 section 4.1.4."""
        pointer = packed_value.find(packed_string)
        return struct.pack(">H", 0xC000 | pointer)

    @staticmethod
    def _pack_string(value: str, string_type: str) -> bytes:
        """Pack utf-8 string."""
        bytes_value = value.encode(string_type)
        value_length = len(bytes_value)

        return struct.pack("<B", value_length) + bytes_value

    def _get_netlogon_response_5(self) -> bytes:
        """Get NetLogon response for version 5."""
        if self.__info["user"] and not self.__info["has_user"]:
            op_code = NetLogonOPCode.LOGON_SAM_USER_UNKNOWN
        else:
            op_code = NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE

        return self._pack_value(
            (
                (op_code, "<H"),
                (self.__root_dse["serverName"], "unicode"),
                (self.__info["user"], "unicode"),
                (self.__root_dse["dnsHostName"][0], "unicode"),
                (self.__info["domain_guid"], "uuid"),
                (uuid.UUID(int=0), "uuid"),
                (self.__root_dse["dnsForestName"][0], "unicode"),
                (self.__root_dse["dnsDomainName"][0], "unicode"),
                (self.__root_dse["dnsHostName"][0], "unicode"),
                (ipaddress.IPv4Address("127.0.0.1").packed, None),
                (DSFlag.PDC_FLAG | DSFlag.DS_FLAG, "<I"),
                (
                    NetLogonNtVersionFlag.NETLOGON_NT_VERSION_1
                    | NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5,
                    "<I",
                ),
                (0xFFFF, "<H"),
                (0xFFFF, "<H"),
            ),
        )

    def _get_netlogon_response_5_ex(self) -> bytes:
        """Get NetLogon response for extended version 5."""
        if self.__info["user"] and not self.__info["has_user"]:
            op_code = NetLogonOPCode.LOGON_SAM_USER_UNKNOWN_EX
        else:
            op_code = NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE_EX

        ds_flags = 0
        for flag in [
            DSFlag.PDC_FLAG,
            DSFlag.LDAP_FLAG,
            DSFlag.DS_FLAG,
            DSFlag.TIMESERV_FLAG,
            DSFlag.CLOSEST_FLAG,
            DSFlag.WRITABLE_FLAG,
            DSFlag.GOOD_TIMESERV_FLAG,
        ]:
            ds_flags |= flag

        domain_guid = uuid.UUID(self.__root_dse["domainGuid"][0])

        return self._pack_value(
            (
                (op_code, "<H"),
                (0, "<H"),
                (ds_flags, "<I"),
                (domain_guid, "uuid"),
                (self.__root_dse["dnsForestName"][0], "utf-8"),
                (self.__root_dse["dnsDomainName"][0], "utf-8"),
                (self.__root_dse["dnsHostName"][0], "utf-8"),
                ("DC", "utf-8"),
                ("DC.ad.local", "utf-8"),
                (self.__info["user"], "utf-8"),
                (self.__info["site"], "utf-8"),
                (self.__info["site"], "utf-8"),
                (
                    NetLogonNtVersionFlag.NETLOGON_NT_VERSION_1
                    | NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5EX,
                    "<I",
                ),
                (0xFFFF, "<H"),
                (0xFFFF, "<H"),
            ),
        )

    def _get_netlogon_response_nt40(self) -> bytes:
        """Get NetLogon response for version 5."""
        if self.__info["user"] and not self.__info["has_user"]:
            op_code = NetLogonOPCode.LOGON_SAM_USER_UNKNOWN
        else:
            op_code = NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE
        return self._pack_value(
            (
                (op_code, "<H"),
                (self.__root_dse["serverName"], "unicode"),
                (self.__info["user"], "unicode"),
                (self.__root_dse["dnsHostName"][0], "unicode"),
                (NetLogonNtVersionFlag.NETLOGON_NT_VERSION_1, "<I"),
                (0xFFFF, "<H"),
                (0xFFFF, "<H"),
            ),
        )
