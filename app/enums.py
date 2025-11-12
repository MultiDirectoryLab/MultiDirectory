"""Enums.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, StrEnum


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


class ApiPermissionsType(StrEnum):
    """API Permissions."""

    PASSWORD_POLICY_GET_ALL = "password_policy_get_all"  # noqa: S105
    PASSWORD_POLICY_GET = "password_policy_get"  # noqa: S105
    PASSWORD_POLICY_GET_BY_DIR = "password_policy_get_by_dir"  # noqa: S105
    PASSWORD_POLICY_UPDATE = "password_policy_update"  # noqa: S105
    PASSWORD_POLICY_RESET_DOMAIN_POLICY = "password_policy_reset_domain_policy"  # noqa: S105
    PASSWORD_POLICY_TURNOFF = "password_policy_turnoff"  # noqa: S105

    NETWORK_POLICY_CREATE = "network_policy_create"
    NETWORK_POLICY_GET_LIST_POLICIES = "network_policy_get_list_policies"
    NETWORK_POLICY_DELETE = "network_policy_delete"
    NETWORK_POLICY_SWITCH_NETWORK_POLICY = (
        "network_policy_switch_network_policy"
    )
    NETWORK_POLICY_SWAP_PRIORITIES = "network_policy_swap_priorities"
    NETWORK_POLICY_UPDATE = "network_policy_update"


    DHCP_CHANGE_STATE = "dhcp_change_state"
    DHCP_GET_STATE = "dhcp_get_state"
    DHCP_CREATE_SUBNET = "dhcp_create_subnet"
    DHCP_DELETE_SUBNET = "dhcp_delete_subnet"
    DHCP_GET_SUBNETS = "dhcp_get_subnets"
    DHCP_UPDATE_SUBNET = "dhcp_update_subnet"
    DHCP_CREATE_LEASE = "dhcp_create_lease"
    DHCP_RELEASE_LEASE = "dhcp_release_lease"
    DHCP_LIST_ACTIVE_LEASES = "dhcp_list_active_leases"
    DHCP_FIND_LEASE = "dhcp_find_lease"
    DHCP_LEASE_TO_RESERVATION = "dhcp_lease_to_reservation"
    DHCP_ADD_RESERVATION = "dhcp_add_reservation"
    DHCP_GET_RESERVATIONS = "dhcp_get_reservations"
    DHCP_UPDATE_RESERVATION = "dhcp_update_reservation"
    DHCP_DELETE_RESERVATION = "dhcp_delete_reservation"
