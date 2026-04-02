"""Data variables.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enums import EntityTypeNames, SamAccountTypeCodes
from ldap_protocol.ldap_schema.dto import EntityTypeDTO

CONFIGURATION_DIR_NAME = "Configuration"
GROUPS_CONTAINER_NAME = "Groups"
COMPUTERS_CONTAINER_NAME = "Computers"
USERS_CONTAINER_NAME = "Users"
DOMAIN_CONTROLLERS_OU_NAME = "Domain Controllers"

READ_ONLY_GROUP_NAME = "read-only"

DOMAIN_ADMIN_GROUP_NAME = "domain admins"
DOMAIN_USERS_GROUP_NAME = "domain users"
DOMAIN_COMPUTERS_GROUP_NAME = "domain computers"


group_attrs = {
    "objectClass": ["top"],
    "groupType": ["-2147483646"],
    "instanceType": ["4"],
    "sAMAccountName": ["groups"],
    "sAMAccountType": [str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value)],
}


DATA = [
    {
        "name": "main",
        "object_class": "builtinDomain",
        "attributes": {
            "objectClass": ["top"],
            "sAMAccountName": ["main"],
        },
        "children": [
            {
                "name": "administrators",
                "object_class": "group",
                "attributes": group_attrs
                | {"sAMAccountName": ["administrators"]},
            },
            {
                "name": "committers",
                "object_class": "group",
                "attributes": group_attrs | {"sAMAccountName": ["committers"]},
            },
            {
                "name": "operators",
                "object_class": "group",
                "attributes": group_attrs | {"sAMAccountName": ["operators"]},
            },
            {
                "name": "guests",
                "object_class": "group",
                "attributes": group_attrs | {"sAMAccountName": ["guests"]},
                "groups": ["operators", "committers"],
            },
        ],
    },
    {
        "name": "it",
        "object_class": "container",
        "attributes": {"objectClass": ["top"]},
        "children": [
            {
                "name": "user 1",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_account_name": "username1",
                    "user_principal_name": "username1@multifactor.dev",
                    "mail": "username1@multifactor.dev",
                    "display_name": "User 1",
                    "password": "password",
                    "groups": ["administrators", "operators"],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                    ],
                },
            },
            {
                "name": "user 2",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_account_name": "username2",
                    "user_principal_name": "username2@multifactor.dev",
                    "mail": "username2@multifactor.dev",
                    "display_name": "User 2",
                    "password": "password",
                    "groups": ["administrators", "operators"],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                    ],
                },
            },
        ],
    },
    {
        "name": "user",
        "object_class": "user",
        "organizationalPerson": {
            "sam_account_name": "username0",
            "user_principal_name": "username0@multifactor.dev",
            "mail": "username0@multifactor.dev",
            "display_name": "User 0",
            "password": "password",
            "groups": ["administrators", "operators"],
        },
        "attributes": {
            "objectClass": [
                "top",
                "person",
                "organizationalPerson",
                "posixAccount",
                "inetOrgPerson",
            ],
        },
    },
    {
        "name": USERS_CONTAINER_NAME,
        "object_class": "container",
        "attributes": {"objectClass": ["top"]},
        "children": [
            {
                "name": "user 3",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_account_name": "username3",
                    "user_principal_name": "username3@multifactor.dev",
                    "mail": "username3@multifactor.dev",
                    "display_name": "User 3",
                    "password": "password",
                    "groups": ["operators", "administrators"],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                    ],
                    "uidNumber": ["20000"],
                    "gidNumber": ["20000"],
                    "loginShell": ["/bin/bash"],
                    "homeDirectory": ["/home/jsmith"],
                    "uid": ["username3"],
                },
            },
            {
                "name": "user 4",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_account_name": "username4",
                    "user_principal_name": "username4@multifactor.dev",
                    "mail": "username4@multifactor.dev",
                    "display_name": "User 4",
                    "password": "password",
                    "groups": ["guests"],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                    ],
                },
            },
        ],
    },
    {
        "name": "2fa",
        "object_class": "container",
        "attributes": {"objectClass": ["top"]},
        "children": [
            {
                "name": "service accounts",
                "object_class": "container",
                "attributes": {"objectClass": ["top"]},
                "children": [
                    {
                        "name": "user 5",
                        "object_class": "user",
                        "organizationalPerson": {
                            "sam_account_name": "username5",
                            "user_principal_name": "username5@multifactor.dev",
                            "mail": "username5@multifactor.dev",
                            "display_name": "User 5",
                            "password": "password",
                        },
                        "attributes": {
                            "objectClass": [
                                "top",
                                "person",
                                "organizationalPerson",
                                "posixAccount",
                                "inetOrgPerson",
                            ],
                        },
                    },
                ],
            },
        ],
    },
]


# NOTE: First time load
ENTITY_TYPE_DTOS_V1: tuple[EntityTypeDTO, ...] = (
    EntityTypeDTO(
        name=EntityTypeNames.DOMAIN,
        is_system=True,
        object_class_names=["top", "domain", "domainDNS"],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.COMPUTER,
        is_system=True,
        object_class_names=["top", "computer"],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.CONTAINER,
        is_system=True,
        object_class_names=["top", "container"],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.ORGANIZATIONAL_UNIT,
        is_system=True,
        object_class_names=["top", "container", "organizationalUnit"],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.GROUP,
        is_system=True,
        object_class_names=["top", "group", "posixGroup"],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.USER,
        is_system=True,
        object_class_names=[
            "top",
            "user",
            "person",
            "organizationalPerson",
            "posixAccount",
            "shadowAccount",
            "inetOrgPerson",
        ],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.CONTACT,
        is_system=True,
        object_class_names=[
            "top",
            "person",
            "organizationalPerson",
            "contact",
            "mailRecipient",
        ],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.KRB_CONTAINER,
        is_system=True,
        object_class_names=["krbContainer"],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.KRB_PRINCIPAL,
        is_system=True,
        object_class_names=[
            "krbprincipal",
            "krbprincipalaux",
            "krbTicketPolicyAux",
        ],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.KRB_REALM_CONTAINER,
        is_system=True,
        object_class_names=["top", "krbrealmcontainer", "krbticketpolicyaux"],
    ),
)

ATTRIBUTE_TYPE_OBJECT_CLASS_NAMES = ["top", "attributeSchema"]
OBJECT_CLASS_OBJECT_CLASS_NAMES = ["top", "classSchema"]

# NOTE: Second time load
ENTITY_TYPE_DTOS_V2: tuple[EntityTypeDTO, ...] = (
    EntityTypeDTO(
        name=EntityTypeNames.CONFIGURATION,
        is_system=True,
        object_class_names=["top", "container", "configuration"],
    ),
    EntityTypeDTO(
        name=EntityTypeNames.ATTRIBUTE_TYPE,
        is_system=True,
        object_class_names=ATTRIBUTE_TYPE_OBJECT_CLASS_NAMES,
    ),
    EntityTypeDTO(
        name=EntityTypeNames.OBJECT_CLASS,
        is_system=True,
        object_class_names=OBJECT_CLASS_OBJECT_CLASS_NAMES,
    ),
)

FIRST_SETUP_DATA = [
    {
        "name": CONFIGURATION_DIR_NAME,
        "entity_type_name": EntityTypeNames.CONFIGURATION,
        "object_class": "container",
        "attributes": {"objectClass": ["top", "configuration"]},
    },
    {
        "name": GROUPS_CONTAINER_NAME,
        "entity_type_name": EntityTypeNames.CONTAINER,
        "object_class": "container",
        "attributes": {
            "objectClass": ["top"],
            "sAMAccountName": ["groups"],
        },
        "children": [
            {
                "name": DOMAIN_ADMIN_GROUP_NAME,
                "entity_type_name": EntityTypeNames.GROUP,
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": [DOMAIN_ADMIN_GROUP_NAME],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                    "gidNumber": ["512"],
                },
                "objectSid": 512,
            },
            {
                "name": DOMAIN_USERS_GROUP_NAME,
                "entity_type_name": EntityTypeNames.GROUP,
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": [DOMAIN_USERS_GROUP_NAME],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                    "gidNumber": ["513"],
                },
                "objectSid": 513,
            },
            {
                "name": READ_ONLY_GROUP_NAME,
                "entity_type_name": EntityTypeNames.GROUP,
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": [READ_ONLY_GROUP_NAME],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                    "gidNumber": ["521"],
                },
                "objectSid": 521,
            },
            {
                "name": DOMAIN_COMPUTERS_GROUP_NAME,
                "entity_type_name": EntityTypeNames.GROUP,
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": [DOMAIN_COMPUTERS_GROUP_NAME],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                    "gidNumber": ["515"],
                },
                "objectSid": 515,
            },
        ],
    },
    {
        "name": COMPUTERS_CONTAINER_NAME,
        "entity_type_name": EntityTypeNames.CONTAINER,
        "object_class": "container",
        "attributes": {"objectClass": ["top"]},
        "children": [],
    },
]


DEFAULT_DC_POSTFIX = "DC1"
UNC_PREFIX = "\\\\"
