"""Retorts for Kea DHCP API.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import Retort, name_mapping

from .dataclasses import DHCPLease, DHCPReservation, DHCPSubnet
from .schemas import (
    KeaDHCPAPILeaseRequest,
    KeaDHCPAPISubnetRequest,
    KeaDHCPBaseAPIRequest,
)

base_retort = Retort()

add_subnet_retort = Retort(
    recipe=[
        name_mapping(
            KeaDHCPAPISubnetRequest,
            map=[
                ("subnet4", ("arguments", "subnet4")),
            ],
        ),
        name_mapping(
            DHCPSubnet,
            map={
                "option_data": "option-data",
            },
        ),
    ],
)

update_subnet_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPSubnet,
            map={
                "option_data": "option-data",
            },
        ),
        name_mapping(
            KeaDHCPAPISubnetRequest,
            map=[
                ("subnet4", ("arguments", "subnet4")),
            ],
        ),
    ],
)

delete_subnet_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPSubnet,
            only="id",
        ),
        name_mapping(
            KeaDHCPAPISubnetRequest,
            map=[
                {"subnet4": "arguments"},
            ],
        ),
    ],
)

list_subnet_retort = base_retort.extend(
    recipe=[
        name_mapping(
            KeaDHCPBaseAPIRequest,
            only=["command", "service"],
        ),
    ],
)

get_subnet_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPSubnet,
            only="id",
        ),
        name_mapping(
            KeaDHCPAPISubnetRequest,
            map=[
                {"subnet4": "arguments"},
            ],
        ),
    ],
)

add_lease_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPLease,
            only=[
                "subnet_id",
                "ip_address",
                "mac_address",
                "hostname",
            ],
            map={
                "subnet_id": "subnet-id",
                "ip_address": "ip-address",
                "mac_address": "hw-address",
            },
        ),
        name_mapping(
            KeaDHCPAPILeaseRequest,
            map={
                "lease": "arguments",
            },
        ),
    ],
)

release_lease_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPLease,
            only="ip_address",
            map={
                "ip_address": "ip-address",
            },
        ),
        name_mapping(
            KeaDHCPAPILeaseRequest,
            map={
                "lease": "arguments",
            },
        ),
    ],
)

list_leases_retort = base_retort.extend(
    recipe=[
        name_mapping(
            KeaDHCPBaseAPIRequest,
            map=[
                ("arguments", ("arguments", "subnets")),
            ],
        ),
    ],
)

get_lease_by_hw_address_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPLease,
            only="mac_address",
            map=[
                {"mac_address": "hw-address"},
            ],
        ),
        name_mapping(
            KeaDHCPAPILeaseRequest,
            map={
                "lease": "arguments",
            },
        ),
    ],
)

get_lease_by_hostname_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPLease,
            only="hostname",
        ),
        name_mapping(
            KeaDHCPAPILeaseRequest,
            map={
                "lease": "arguments",
            },
        ),
    ],
)

add_reservation_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPReservation,
            only=[
                "ip_address",
                "mac_address",
                "hostname",
                "subnet_id",
                "operation_target",
            ],
        ),
        name_mapping(
            DHCPReservation,
            map=[
                ("ip_address", ("reservation", "ip-address")),
                ("mac_address", ("reservation", "hw-address")),
                (
                    "hostname",
                    ("reservation", "hostname"),
                ),
                ("subnet_id", ("reservation", "subnet-id")),
                ("operation_target", ("operation-target")),
            ],
        ),
    ],
)

delete_reservation_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPReservation,
            only=[
                "subnet_id",
                "ip_address",
                "identifier_type",
                "identifier",
                "operation_target",
            ],
            map={
                "subnet_id": "subnet-id",
                "ip_address": "ip-address",
                "identifier_type": "identifier-type",
                "operation_target": "operation-target",
            },
        ),
    ],
)

get_all_reservations_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPReservation,
            only=[
                "subnet_id",
                "operation_target",
            ],
            map=[
                {"subnet_id": "subnet-id"},
                {"operation_target": "operation-target"},
            ],
        ),
    ],
)
