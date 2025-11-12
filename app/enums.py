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

    ATTRIBUTE_TYPE_GET = "attribute_type_get"
    ATTRIBUTE_TYPE_CREATE = "attribute_type_create"
    ATTRIBUTE_TYPE_GET_PAGINATOR = "attribute_type_get_paginator"
    ATTRIBUTE_TYPE_UPDATE = "attribute_type_update"
    ATTRIBUTE_TYPE_DELETE_ALL_BY_NAMES = "attribute_type_delete_all_by_names"

    ENTITY_TYPE_GET = "entity_type_get"
    ENTITY_TYPE_CREATE = "entity_type_create"
    ENTITY_TYPE_GET_PAGINATOR = "entity_type_get_paginator"
    ENTITY_TYPE_UPDATE = "entity_type_update"
    ENTITY_TYPE_DELETE_ALL_BY_NAMES = "entity_type_delete_all_by_names"
    ENTITY_TYPE_GET_ATTRIBUTES = "entity_type_get_attributes"

    OBJECT_CLASS_GET = "object_class_get"
    OBJECT_CLASS_CREATE = "object_class_create"
    OBJECT_CLASS_GET_PAGINATOR = "object_class_get_paginator"
    OBJECT_CLASS_UPDATE = "object_class_update"
    OBJECT_CLASS_DELETE_ALL_BY_NAMES = "object_class_delete_all_by_names"

    DNS_SETUP_DNS = "dns_setup_dns"
    DNS_CREATE_RECORD = "dns_create_record"
    DNS_DELETE_RECORD = "dns_delete_record"
    DNS_UPDATE_RECORD = "dns_update_record"
    DNS_GET_ALL_RECORDS = "dns_get_all_records"
    DNS_GET_DNS_STATUS = "dns_get_dns_status"
    DNS_GET_ALL_ZONES_RECORDS = "dns_get_all_zones_records"
    DNS_GET_FORWARD_ZONES = "dns_get_forward_zones"
    DNS_CREATE_ZONE = "dns_create_zone"
    DNS_UPDATE_ZONE = "dns_update_zone"
    DNS_DELETE_ZONE = "dns_delete_zone"
    DNS_CHECK_DNS_FORWARD_ZONE = "dns_check_dns_forward_zone"
    DNS_RELOAD_ZONE = "dns_reload_zone"
    DNS_UPDATE_SERVER_OPTIONS = "dns_update_server_options"
    DNS_GET_SERVER_OPTIONS = "dns_get_server_options"
    DNS_RESTART_SERVER = "dns_restart_server"

    KRB_SETUP_CATALOGUE = "krb_setup_catalogue"
    KRB_SETUP_KDC = "krb_setup_kdc"
    KRB_KTADD = "krb_ktadd"
    KRB_GET_STATUS = "krb_get_status"
    KRB_ADD_PRINCIPAL = "krb_add_principal"
    KRB_RENAME_PRINCIPAL = "krb_rename_principal"
    KRB_RESET_PRINCIPAL_PW = "krb_reset_principal_pw"
    KRB_DELETE_PRINCIPAL = "krb_delete_principal"

    AUDIT_GET_POLICIES = "audit_get_policies"
    AUDIT_UPDATE_POLICY = "audit_update_policy"
    AUDIT_GET_DESTINATIONS = "audit_get_destinations"
    AUDIT_CREATE_DESTINATION = "audit_create_destination"
    AUDIT_DELETE_DESTINATION = "audit_delete_destination"
    AUDIT_UPDATE_DESTINATION = "audit_update_destination"

    AUTH_RESET_PASSWORD = "auth_reset_password"