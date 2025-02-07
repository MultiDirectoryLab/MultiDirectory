"""NetLogon attribute handler.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import ipaddress
import socket
import struct
import uuid
from collections import defaultdict
from enum import IntEnum, IntFlag
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.user_account_control import (
    UserAccountControlFlag,
    get_check_uac,
)
from ldap_protocol.utils.queries import get_user


class NetLogonOPCode(IntEnum):
    """NetLogon operational codes."""

    LOGON_PRIMARY_RESPONSE = 12
    LOGON_SAM_LOGON_RESPONSE = 19
    LOGON_SAM_PAUSE_RESPONSE = 20
    LOGON_SAM_USER_UNKNOWN = 21
    LOGON_SAM_LOGON_RESPONSE_EX = 23
    LOGON_SAM_PAUSE_RESPONSE_EX = 24
    LOGON_SAM_USER_UNKNOWN_EX = 25


class DSFlag(IntFlag):
    """Domain controller flags mapping."""

    DS_PDC_FLAG = 0x00000001
    DS_GC_FLAG = 0x00000004
    DS_LDAP_FLAG = 0x00000008
    DS_DS_FLAG = 0x00000010
    DS_KDC_FLAG = 0x00000020
    DS_TIMESERV_FLAG = 0x00000040
    DS_CLOSEST_FLAG = 0x00000080
    DS_WRITABLE_FLAG = 0x00000100
    DS_GOOD_TIMESERV_FLAG = 0x00000200
    DS_NDNC_FLAG = 0x00000400
    DS_SELECT_SECRET_DOMAIN_6_FLAG = 0x00000800
    DS_FULL_SECRET_DOMAIN_6_FLAG = 0x00001000
    DS_WS_FLAG = 0x00002000
    DS_PING_FLAGS = 0x00004000
    DS_DNS_CONTROLLER_FLAG = 0x20000000
    DS_DNS_DOMAIN_FLAG = 0x40000000
    DS_DNS_FOREST_FLAG = 0x80000000


class NetLogonNtVersionFlag(IntFlag):
    """Netlogon NT version flags mapping."""

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


class NetLogonAttributeFilter:
    """NetLogon attribute filter handler."""

    dnsdomain: str | None = None
    host: str | None = None
    dnshostname: str | None = None
    user: str | None = None
    aac: int | None = None
    domainsid: str | None = None
    domainguid: uuid.UUID | None = None
    ntver: int = 0x00000000

    @classmethod
    async def is_netlogon_filter(cls, expr: ASN1Row) -> bool:
        """Check if filter is requesting NetLogon attribute."""
        has_ntver = False

        if expr.tag_id == 0:
            for item in expr.value:
                if item.tag_id in range(3):
                    return False
                attr, _ = item.value
                if attr.value.lower() == "ntver":
                    has_ntver = True
                    break

        return has_ntver

    @classmethod
    async def get_info_from_filter(
        cls,
        expr: ASN1Row,
        session: AsyncSession,
        root_dse: defaultdict[str, list[str]],
    ) -> dict[str, Any]:
        """Get info from filter."""
        info: dict[str, Any] = {}
        filter_obj = await cls._parse_filter(expr)

        if filter_obj.domainguid is not None:
            info["domain_guid"] = filter_obj.domainguid
        else:
            info["domain_guid"] = uuid.UUID(int=0)

        if filter_obj.dnsdomain is not None:
            info["domain_dns"] = filter_obj.dnsdomain
        else:
            if info["domain_guid"] == uuid.UUID(int=0):
                info["domain_dns"] = root_dse["dnsHostName"][0]
            else:
                info["domain_dns"] = ""

        if info["domain_guid"] == uuid.UUID(int=0):
            info["nc_used"] = info["domain_dns"]
        else:
            info["nc_used"] = info["domain_guid"]

        if filter_obj.domainsid is not None:
            info["domain_sid"] = filter_obj.domainsid
        else:
            info["domain_sid"] = ""

        if filter_obj.user is not None:
            info["user"] = filter_obj.user
        else:
            info["user"] = ""

        user_obj = await get_user(session, info["user"])
        if user_obj is not None:
            if filter_obj.aac is not None:
                aac = filter_obj.aac
            else:
                aac = 0

            uac_check = await get_check_uac(session, user_obj.directory_id)
            if uac_check(UserAccountControlFlag.ACCOUNTDISABLE):
                info["has_user"] = False
            else:
                if aac and (
                    uac_check(
                        UserAccountControlFlag.TEMP_DUPLICATE_ACCOUNT) or
                    uac_check(
                        UserAccountControlFlag.NORMAL_ACCOUNT) or
                    uac_check(
                        UserAccountControlFlag.INTERDOMAIN_TRUST_ACCOUNT) or
                    uac_check(
                        UserAccountControlFlag.WORKSTATION_TRUST_ACCOUNT) or
                    uac_check(
                        UserAccountControlFlag.SERVER_TRUST_ACCOUNT)
                ):
                    info["has_user"] = False
                else:
                    info["has_user"] = True
        else:
            info["has_user"] = False

        info["site"] = "Default-First-Site-Name"
        info["ntver"] = filter_obj.ntver
        return info

    @classmethod
    async def _parse_filter(cls, expr: ASN1Row) -> "NetLogonAttributeFilter":
        """Parse NetLogon filter."""
        obj = cls()

        for item in expr.value:
            attr, value = item.value

            if hasattr(obj, attr.value.lower()):
                obj.__setattr__(
                    attr.value.lower(),
                    value.value,
                )

        return obj


class NetLogonAttributeHandler:
    """NetLogon attribute handler."""

    @classmethod
    async def get_netlogon_attr(
        cls,
        session: AsyncSession,
        expr: ASN1Row,
        root_dse: defaultdict[str, list[str]],
    ) -> bytes:
        """Get NetLogon attribute."""
        return await cls._get_netlogon_packed_value(
            session,
            expr,
            root_dse,
        )

    @staticmethod
    def _convert_little_endian_string_to_int(value: str) -> int:
        """Convert little-endian string to int."""
        return int.from_bytes(
            value.encode().decode("unicode_escape").encode(),
            byteorder="little",
            signed=False,
        )

    @classmethod
    async def _get_netlogon_packed_value(
        cls,
        session: AsyncSession,
        expr: ASN1Row,
        root_dse: defaultdict[str, list[str]],
    ) -> bytes:
        """Get NetLogon response."""
        info = await NetLogonAttributeFilter.get_info_from_filter(
            expr,
            session,
            root_dse,
        )
        if bool(
            cls._convert_little_endian_string_to_int(info["ntver"]) &
            NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5EX,
        ) or bool(
            cls._convert_little_endian_string_to_int(info["ntver"]) &
            NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5EX_WITH_IP,
        ):
            return await cls._get_netlogon_response_5_ex(info, root_dse)

        if bool(
            cls._convert_little_endian_string_to_int(info["ntver"]) &
            NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5,
        ):
            return await cls._get_netlogon_response_5(
                info,
                root_dse,
            )

        return await cls._get_netlogon_response_nt40(info, root_dse)

    @classmethod
    def _pack_value(cls, values: tuple) -> bytes:
        """Pack values."""
        packed_value = b""
        for value in values:
            if value[0] is None:
                continue
            if value[1] in ["utf-8", "unicode"]:
                packed_string = cls._pack_string(value[0], value[1])
                if len(value[1]) > 0:
                    packed_string += struct.pack("<B", 0)
                    if packed_string in packed_value:
                        packed_value += cls._get_pointer(
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

    @classmethod
    def _get_pointer(cls, packed_string: bytes, packed_value: bytes) -> bytes:
        """Get pointer, reference RFC 1035 section 4.1.4."""
        pointer = packed_value.find(packed_string)
        return struct.pack(">H", 0xC000 | pointer)

    @classmethod
    def _pack_string(cls, value: str, string_type: str) -> bytes:
        """Pack utf-8 string."""
        bytes_value = value.encode(string_type)
        value_length = len(bytes_value)

        return struct.pack("<B", value_length) + bytes_value

    @classmethod
    async def _get_netlogon_response_5(
        cls,
        info: dict[str, Any],
        root_dse: defaultdict[str, list[str]],
    ) -> bytes:
        """Get NetLogon response for version 5."""
        if info["user"] and not info["has_user"]:
            op_code = NetLogonOPCode.LOGON_SAM_USER_UNKNOWN
        else:
            op_code = NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE

        return cls._pack_value(
            (
                (op_code, "<H"),
                (root_dse["serverName"], "unicode"),
                (info["user"], "unicode"),
                (root_dse["dnsHostName"][0], "unicode"),
                (info["domain_guid"], "uuid"),
                (uuid.UUID(int=0), "uuid"),
                (root_dse["dnsForestName"][0], "unicode"),
                (root_dse["dnsDomainName"][0], "unicode"),
                (root_dse["dnsHostName"][0], "unicode"),
                (ipaddress.IPv4Address("127.0.0.1").packed, None),
                (DSFlag.DS_PDC_FLAG | DSFlag.DS_DS_FLAG, "<I"),
                (
                    NetLogonNtVersionFlag.NETLOGON_NT_VERSION_1 |
                    NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5, "<I",
                ),
                (0xFFFF, "<H"),
                (0xFFFF, "<H"),
            ),
        )

    @classmethod
    async def _get_netlogon_response_5_ex(
        cls,
        info: dict[str, Any],
        root_dse: defaultdict[str, list[str]],
    ) -> bytes:
        """Get NetLogon response for extended version 5."""
        if info["user"] and not info["has_user"]:
            op_code = NetLogonOPCode.LOGON_SAM_USER_UNKNOWN_EX
        else:
            op_code = NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE_EX

        ds_flags = 0
        for flag in [
            DSFlag.DS_PDC_FLAG, DSFlag.DS_GC_FLAG,
            DSFlag.DS_LDAP_FLAG, DSFlag.DS_DS_FLAG,
            DSFlag.DS_KDC_FLAG, DSFlag.DS_TIMESERV_FLAG,
            DSFlag.DS_CLOSEST_FLAG, DSFlag.DS_WRITABLE_FLAG,
            DSFlag.DS_GOOD_TIMESERV_FLAG,
        ]:
            ds_flags |= flag

        domain_guid = uuid.UUID(root_dse["domainGuid"][0])
        netbios_name = socket.gethostname()

        return cls._pack_value(
            (
                (op_code, "<H"),
                (0, "<H"),
                (ds_flags, "<I"),
                (domain_guid, "uuid"),
                (root_dse["dnsForestName"][0], "utf-8"),
                (root_dse["dnsDomainName"][0], "utf-8"),
                (root_dse["dnsHostName"][0], "utf-8"),
                (netbios_name, "utf-8"),
                (netbios_name, "utf-8"),
                (info["user"], "utf-8"),
                (info["site"], "utf-8"),
                (info["site"], "utf-8"),
                (
                    NetLogonNtVersionFlag.NETLOGON_NT_VERSION_1 |
                    NetLogonNtVersionFlag.NETLOGON_NT_VERSION_5EX, "<I",
                ),
                (0xFFFF, "<H"),
                (0xFFFF, "<H"),
            ),
        )

    @classmethod
    async def _get_netlogon_response_nt40(
        cls,
        info: dict[str, Any],
        root_dse: defaultdict[str, list[str]],
    ) -> bytes:
        """Get NetLogon response for version 5."""
        if info["user"] and not info["has_user"]:
            op_code = NetLogonOPCode.LOGON_SAM_USER_UNKNOWN
        else:
            op_code = NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE
        return cls._pack_value(
            (
                (op_code, "<H"),
                (root_dse["serverName"], "unicode"),
                (info["user"], "unicode"),
                (root_dse["dnsHostName"][0], "unicode"),
                (NetLogonNtVersionFlag.NETLOGON_NT_VERSION_1, "<I"),
                (0xFFFF, "<H"),
                (0xFFFF, "<H"),
            ),
        )
