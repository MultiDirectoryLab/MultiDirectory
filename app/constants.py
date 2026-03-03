"""Data variables.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import TypedDict

from enums import EntityTypeNames, SamAccountTypeCodes

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


class EntityTypeData(TypedDict):
    """Entity Type data."""

    name: EntityTypeNames
    object_class_names: list[str]


ENTITY_TYPE_DATAS: tuple[EntityTypeData, ...] = (
    EntityTypeData(
        name=EntityTypeNames.DOMAIN,
        object_class_names=["top", "domain", "domainDNS"],
    ),
    EntityTypeData(
        name=EntityTypeNames.CONFIGURATION,
        object_class_names=["top", "container", "configuration"],
    ),
    EntityTypeData(
        name=EntityTypeNames.ATTRIBUTE_TYPE,
        object_class_names=["top", "attributeSchema"],
    ),
    EntityTypeData(
        name=EntityTypeNames.OBJECT_CLASS,
        object_class_names=["top", "classSchema"],
    ),
    EntityTypeData(
        name=EntityTypeNames.COMPUTER,
        object_class_names=["top", "computer"],
    ),
    EntityTypeData(
        name=EntityTypeNames.CONTAINER,
        object_class_names=["top", "container"],
    ),
    EntityTypeData(
        name=EntityTypeNames.ORGANIZATIONAL_UNIT,
        object_class_names=["top", "container", "organizationalUnit"],
    ),
    EntityTypeData(
        name=EntityTypeNames.GROUP,
        object_class_names=["top", "group", "posixGroup"],
    ),
    EntityTypeData(
        name=EntityTypeNames.USER,
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
    EntityTypeData(
        name=EntityTypeNames.CONTACT,
        object_class_names=[
            "top",
            "person",
            "organizationalPerson",
            "contact",
            "mailRecipient",
        ],
    ),
    EntityTypeData(
        name=EntityTypeNames.KRB_CONTAINER,
        object_class_names=["krbContainer"],
    ),
    EntityTypeData(
        name=EntityTypeNames.KRB_PRINCIPAL,
        object_class_names=[
            "krbprincipal",
            "krbprincipalaux",
            "krbTicketPolicyAux",
        ],
    ),
    EntityTypeData(
        name=EntityTypeNames.KRB_REALM_CONTAINER,
        object_class_names=["top", "krbrealmcontainer", "krbticketpolicyaux"],
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
