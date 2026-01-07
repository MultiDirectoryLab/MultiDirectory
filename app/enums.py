"""Enums.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from __future__ import annotations

from enum import UNIQUE, IntEnum, IntFlag, StrEnum, auto, verify
from functools import reduce
from operator import or_
from typing import Iterable, Self


class AceType(IntEnum):
    """ACE types."""

    CREATE_CHILD = 1
    READ = 2
    WRITE = 3
    DELETE = 4
    PASSWORD_MODIFY = 5


class RoleScope(IntEnum):
    """Scope of the role."""

    BASE_OBJECT = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2


class MFAFlags(IntEnum):
    """Two-Factor auth action."""

    DISABLED = 0
    ENABLED = 1
    WHITELIST = 2


class MFAChallengeStatuses(StrEnum):
    """Two-Factor challenge status."""

    BYPASS = "bypass"
    PENDING = "pending"


class EntityTypeNames(StrEnum):
    """Enum of base (system) Entity Types.

    Used for system objects.
    Custom Entity Types aren't included here.
    """

    DOMAIN = "Domain"
    COMPUTER = "Computer"
    CONTAINER = "Container"
    ORGANIZATIONAL_UNIT = "Organizational Unit"
    GROUP = "Group"
    USER = "User"
    KRB_CONTAINER = "KRB Container"
    KRB_PRINCIPAL = "KRB Principal"
    KRB_REALM_CONTAINER = "KRB Realm Container"


class KindType(StrEnum):
    """Object kind types."""

    STRUCTURAL = "STRUCTURAL"
    ABSTRACT = "ABSTRACT"
    AUXILIARY = "AUXILIARY"


class AuditSeverity(IntEnum):
    """Audit policy severity."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


class AuditDestinationProtocolType(StrEnum):
    """Audit destination protocol type."""

    UDP = "udp"
    TCP = "tcp"


class AuditDestinationServiceType(StrEnum):
    """Audit destination type."""

    SYSLOG = "syslog"


class RoleConstants(StrEnum):
    """Role constants."""

    DOMAIN_ADMINS_ROLE_NAME = "Domain Admins Role"
    READ_ONLY_ROLE_NAME = "Read Only Role"
    KERBEROS_ROLE_NAME = "Kerberos Role"

    DOMAIN_ADMINS_GROUP_CN = "cn=domain admins,cn=groups,"
    READONLY_GROUP_CN = "cn=read-only,cn=groups,"
    KERBEROS_GROUP_CN = "cn=krbadmin,cn=groups,"


@verify(UNIQUE)
class AuthorizationRules(IntFlag):
    """API Permissions."""

    PASSWORD_POLICY_GET_ALL = auto()
    PASSWORD_POLICY_GET = auto()
    PASSWORD_POLICY_GET_BY_DIR = auto()
    PASSWORD_POLICY_UPDATE = auto()
    PASSWORD_POLICY_RESET_DOMAIN_POLICY = auto()
    PASSWORD_BAN_WORD_GET_ALL = auto()
    PASSWORD_BAN_WORD_REPLACE_ALL = auto()

    NETWORK_POLICY_CREATE = auto()
    NETWORK_POLICY_GET_LIST_POLICIES = auto()
    NETWORK_POLICY_DELETE = auto()
    NETWORK_POLICY_SWITCH_NETWORK_POLICY = auto()
    NETWORK_POLICY_SWAP_PRIORITIES = auto()
    NETWORK_POLICY_UPDATE = auto()

    DHCP_CHANGE_STATE = auto()
    DHCP_GET_STATE = auto()
    DHCP_CREATE_SUBNET = auto()
    DHCP_DELETE_SUBNET = auto()
    DHCP_GET_SUBNETS = auto()
    DHCP_UPDATE_SUBNET = auto()
    DHCP_CREATE_LEASE = auto()
    DHCP_RELEASE_LEASE = auto()
    DHCP_LIST_ACTIVE_LEASES = auto()
    DHCP_FIND_LEASE = auto()
    DHCP_LEASE_TO_RESERVATION = auto()
    DHCP_ADD_RESERVATION = auto()
    DHCP_GET_RESERVATIONS = auto()
    DHCP_UPDATE_RESERVATION = auto()
    DHCP_DELETE_RESERVATION = auto()

    ATTRIBUTE_TYPE_GET = auto()
    ATTRIBUTE_TYPE_CREATE = auto()
    ATTRIBUTE_TYPE_GET_PAGINATOR = auto()
    ATTRIBUTE_TYPE_UPDATE = auto()
    ATTRIBUTE_TYPE_DELETE_ALL_BY_NAMES = auto()

    ENTITY_TYPE_GET = auto()
    ENTITY_TYPE_CREATE = auto()
    ENTITY_TYPE_GET_PAGINATOR = auto()
    ENTITY_TYPE_UPDATE = auto()
    ENTITY_TYPE_DELETE_ALL_BY_NAMES = auto()
    ENTITY_TYPE_GET_ATTRIBUTES = auto()

    OBJECT_CLASS_GET = auto()
    OBJECT_CLASS_CREATE = auto()
    OBJECT_CLASS_GET_PAGINATOR = auto()
    OBJECT_CLASS_UPDATE = auto()
    OBJECT_CLASS_DELETE_ALL_BY_NAMES = auto()

    DNS_SETUP_DNS = auto()
    DNS_CREATE_RECORD = auto()
    DNS_DELETE_RECORD = auto()
    DNS_UPDATE_RECORD = auto()
    DNS_GET_ALL_RECORDS = auto()
    DNS_GET_DNS_STATUS = auto()
    DNS_GET_ALL_ZONES_RECORDS = auto()
    DNS_GET_FORWARD_ZONES = auto()
    DNS_CREATE_ZONE = auto()
    DNS_UPDATE_ZONE = auto()
    DNS_DELETE_ZONE = auto()
    DNS_CHECK_DNS_FORWARD_ZONE = auto()
    DNS_RELOAD_ZONE = auto()
    DNS_UPDATE_SERVER_OPTIONS = auto()
    DNS_GET_SERVER_OPTIONS = auto()
    DNS_RESTART_SERVER = auto()

    KRB_SETUP_CATALOGUE = auto()
    KRB_SETUP_KDC = auto()
    KRB_KTADD = auto()
    KRB_GET_STATUS = auto()
    KRB_ADD_PRINCIPAL = auto()
    KRB_RENAME_PRINCIPAL = auto()
    KRB_RESET_PRINCIPAL_PW = auto()
    KRB_DELETE_PRINCIPAL = auto()

    AUDIT_GET_POLICIES = auto()
    AUDIT_UPDATE_POLICY = auto()
    AUDIT_GET_DESTINATIONS = auto()
    AUDIT_CREATE_DESTINATION = auto()
    AUDIT_DELETE_DESTINATION = auto()
    AUDIT_UPDATE_DESTINATION = auto()

    AUTH_RESET_PASSWORD = auto()
    AUTH_LOGIN = auto()

    MFA_SETUP = auto()
    MFA_REMOVE = auto()
    MFA_GET = auto()

    SESSION_GET_USER_SESSIONS = auto()
    SESSION_CLEAR_USER_SESSIONS = auto()
    SESSION_DELETE = auto()

    NETWORK_POLICY_VALIDATOR_GET_BY_PROTOCOL = auto()
    NETWORK_POLICY_VALIDATOR_GET_USER_NETWORK_POLICY = auto()
    NETWORK_POLICY_VALIDATOR_GET_USER_HTTP_POLICY = auto()
    NETWORK_POLICY_VALIDATOR_GET_USER_KERBEROS_POLICY = auto()
    NETWORK_POLICY_VALIDATOR_GET_USER_LDAP_POLICY = auto()
    NETWORK_POLICY_VALIDATOR_IS_USER_GROUP_VALID = auto()
    NETWORK_POLICY_VALIDATOR_CHECK_MFA_GROUP = auto()

    USER_CLEAR_PASSWORD_HISTORY = auto()

    @classmethod
    def get_all(cls) -> Self:
        return cls(sum(cls))

    @staticmethod
    def combine(
        permissions: Iterable[AuthorizationRules],
    ) -> AuthorizationRules:
        return reduce(or_, permissions, AuthorizationRules(0))


class ProtocolType(StrEnum):
    """Protocol fields."""

    LDAP = "is_ldap"
    HTTP = "is_http"
    KERBEROS = "is_kerberos"


class DomainCodes(IntEnum):
    """Error code parts."""

    AUDIT = 1
    AUTH = 2
    SESSION = 3
    DNS = 4
    GENERAL = 5
    KERBEROS = 6
    LDAP = 7
    MFA = 8
    NETWORK = 9
    PASSWORD_POLICY = 10
    ROLES = 11
    DHCP = 12
    LDAP_SCHEMA = 13
    SHADOW = 14
