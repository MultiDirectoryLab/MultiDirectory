"""Data variables for tests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from constants import (
    DOMAIN_ADMIN_GROUP_NAME,
    DOMAIN_COMPUTERS_GROUP_NAME,
    DOMAIN_USERS_GROUP_NAME,
    GROUPS_CONTAINER_NAME,
    USERS_CONTAINER_NAME,
)
from enums import SamAccountTypeCodes
from ldap_protocol.objects import UserAccountControlFlag

TEST_DATA = [
    {
        "name": GROUPS_CONTAINER_NAME,
        "object_class": "container",
        "is_system": False,
        "attributes": {
            "objectClass": ["top"],
            "sAMAccountName": ["groups"],
        },
        "children": [
            {
                "name": DOMAIN_ADMIN_GROUP_NAME,
                "object_class": "group",
                "is_system": False,
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": [DOMAIN_ADMIN_GROUP_NAME],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                },
            },
            {
                "name": "developers",
                "object_class": "group",
                "is_system": False,
                "groups": [DOMAIN_ADMIN_GROUP_NAME],
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["developers"],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                },
            },
            {
                "name": "admin login only",
                "object_class": "group",
                "is_system": False,
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["admin login only"],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                },
            },
            {
                "name": DOMAIN_USERS_GROUP_NAME,
                "object_class": "group",
                "is_system": False,
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": [DOMAIN_USERS_GROUP_NAME],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                },
            },
            {
                "name": DOMAIN_COMPUTERS_GROUP_NAME,
                "object_class": "group",
                "is_system": False,
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": [DOMAIN_COMPUTERS_GROUP_NAME],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                },
            },
        ],
    },
    {
        "name": USERS_CONTAINER_NAME,
        "object_class": "container",
        "is_system": False,
        "attributes": {"objectClass": ["top"]},
        "children": [
            {
                "name": "user0",
                "object_class": "user",
                "is_system": False,
                "organizationalPerson": {
                    "sam_account_name": "user0",
                    "user_principal_name": "user0",
                    "mail": "user0@mail.com",
                    "display_name": "user0",
                    "password": "password",
                    "groups": [DOMAIN_ADMIN_GROUP_NAME],
                },
                "attributes": {
                    "givenName": ["John"],
                    "surname": ["Lennon"],
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                        "shadowAccount",
                    ],
                    "posixEmail": ["abctest@mail.com"],
                    "attr_with_bvalue": [b"any"],
                    "userAccountControl": [
                        str(UserAccountControlFlag.NORMAL_ACCOUNT),
                    ],
                    "description": ["123 desc"],
                },
            },
            {
                "name": "user_admin",
                "object_class": "user",
                "is_system": False,
                "organizationalPerson": {
                    "sam_account_name": "user_admin",
                    "user_principal_name": "user_admin",
                    "mail": "user_admin@mail.com",
                    "display_name": "user_admin",
                    "password": "password",
                    "groups": [DOMAIN_ADMIN_GROUP_NAME],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                        "shadowAccount",
                    ],
                    "posixEmail": ["abctest@mail.com"],
                    "attr_with_bvalue": [b"any"],
                    "userAccountControl": [
                        str(UserAccountControlFlag.NORMAL_ACCOUNT),
                    ],
                },
            },
            {
                "name": "user_admin_for_roles",
                "object_class": "user",
                "is_system": False,
                "organizationalPerson": {
                    "sam_account_name": "user_admin_for_roles",
                    "user_principal_name": "user_admin_for_roles",
                    "mail": "user_admin_for_roles@mail.com",
                    "display_name": "user_admin_for_roles",
                    "password": "password",
                    "groups": ["admin login only"],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                        "shadowAccount",
                    ],
                    "posixEmail": ["abctest@mail.com"],
                    "attr_with_bvalue": [b"any"],
                    "userAccountControl": [
                        str(UserAccountControlFlag.NORMAL_ACCOUNT),
                    ],
                },
            },
            {
                "name": "user_non_admin",
                "object_class": "user",
                "is_system": False,
                "organizationalPerson": {
                    "sam_account_name": "user_non_admin",
                    "user_principal_name": "user_non_admin",
                    "mail": "user_non_admin@mail.com",
                    "display_name": "user_non_admin",
                    "password": "password",
                    "groups": [DOMAIN_USERS_GROUP_NAME],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "user",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                        "shadowAccount",
                    ],
                    "posixEmail": ["abctest@mail.com"],
                    "attr_with_bvalue": [b"any"],
                    "userAccountControl": [
                        str(UserAccountControlFlag.NORMAL_ACCOUNT),
                    ],
                },
            },
            {
                "name": "russia",
                "object_class": "container",
                "is_system": False,
                "attributes": {
                    "objectClass": ["top"],
                    "sAMAccountName": ["groups"],
                },
                "children": [
                    {
                        "name": "moscow",
                        "object_class": "container",
                        "is_system": False,
                        "attributes": {
                            "objectClass": ["top"],
                            "sAMAccountName": ["groups"],
                        },
                        "children": [
                            {
                                "name": "user1",
                                "object_class": "user",
                                "is_system": False,
                                "organizationalPerson": {
                                    "sam_account_name": "user1",
                                    "user_principal_name": "user1",
                                    "mail": "user1@mail.com",
                                    "display_name": "user1",
                                    "password": "password",
                                    "groups": ["developers"],
                                },
                                "attributes": {
                                    "objectClass": [
                                        "top",
                                        "user",
                                        "person",
                                        "organizationalPerson",
                                        "posixAccount",
                                        "shadowAccount",
                                        "inetOrgPerson",
                                    ],
                                    "posixEmail": ["user1@mail.com"],
                                    "userAccountControl": [
                                        str(
                                            UserAccountControlFlag.NORMAL_ACCOUNT,
                                        ),
                                    ],
                                },
                            },
                        ],
                    },
                ],
            },
        ],
    },
    {
        "name": "test_bit_rules",
        "object_class": "organizationalUnit",
        "is_system": False,
        "attributes": {"objectClass": ["top", "container"]},
        "children": [
            {
                "name": "user_admin_1",
                "object_class": "user",
                "is_system": False,
                "organizationalPerson": {
                    "sam_account_name": "user_admin_1",
                    "user_principal_name": "user_admin_1",
                    "mail": "user_admin_1@mail.com",
                    "display_name": "user_admin_1",
                    "password": "password",
                    "groups": [],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                        "shadowAccount",
                    ],
                    "posixEmail": ["abctest321@mail.com"],
                    "attr_with_bvalue": [b"any"],
                    "userAccountControl": [
                        str(
                            UserAccountControlFlag.NOT_DELEGATED
                            + UserAccountControlFlag.NORMAL_ACCOUNT
                            + UserAccountControlFlag.LOCKOUT
                            + UserAccountControlFlag.ACCOUNTDISABLE,
                        ),
                    ],
                },
            },
            {
                "name": "user_admin_2",
                "object_class": "user",
                "is_system": False,
                "organizationalPerson": {
                    "sam_account_name": "user_admin_2",
                    "user_principal_name": "user_admin_2",
                    "mail": "user_admin_2@mail.com",
                    "display_name": "user_admin_2",
                    "password": "password",
                    "groups": [],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                        "shadowAccount",
                    ],
                    "posixEmail": ["abctest123@mail.com"],
                    "attr_with_bvalue": [b"any"],
                    "userAccountControl": [
                        str(
                            UserAccountControlFlag.NOT_DELEGATED
                            + UserAccountControlFlag.NORMAL_ACCOUNT,
                        ),
                    ],
                },
            },
            {
                "name": "user_admin_3",
                "object_class": "user",
                "is_system": False,
                "organizationalPerson": {
                    "sam_account_name": "user_admin_3",
                    "user_principal_name": "user_admin_3",
                    "mail": "user_admin_3@mail.com",
                    "display_name": "user_admin_3",
                    "password": "password",
                    "groups": [],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                        "shadowAccount",
                    ],
                    "posixEmail": ["abctest123@mail.com"],
                    "attr_with_bvalue": [b"any"],
                    "userAccountControl": [
                        str(UserAccountControlFlag.ACCOUNTDISABLE),
                    ],
                },
            },
        ],
    },
    {
        "name": "testModifyDn1",
        "object_class": "organizationalUnit",
        "is_system": False,
        "attributes": {
            "objectClass": ["top", "container"],
            "sAMAccountName": ["testModifyDn1"],
        },
        "children": [
            {
                "name": "testModifyDn2",
                "object_class": "organizationalUnit",
                "is_system": False,
                "attributes": {
                    "objectClass": ["top", "container"],
                    "sAMAccountName": ["testModifyDn2"],
                },
                "children": [
                    {
                        "name": "testGroup1",
                        "object_class": "group",
                        "is_system": False,
                        "attributes": {
                            "objectClass": ["top", "posixGroup"],
                            "groupType": ["-2147483646"],
                            "instanceType": ["4"],
                            "sAMAccountName": ["testGroup1"],
                            "sAMAccountType": [
                                str(
                                    SamAccountTypeCodes.SAM_GROUP_OBJECT.value,
                                ),
                            ],
                        },
                    },
                ],
            },
            {
                "name": "testGroup2",
                "object_class": "group",
                "is_system": False,
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["testGroup2"],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                },
            },
        ],
    },
    {
        "name": "testModifyDn3",
        "object_class": "organizationalUnit",
        "is_system": False,
        "attributes": {
            "objectClass": ["top", "container"],
            "sAMAccountName": ["testModifyDn3"],
        },
        "children": [
            {
                "name": "testGroup3",
                "object_class": "group",
                "is_system": False,
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["testGroup3"],
                    "sAMAccountType": [
                        str(SamAccountTypeCodes.SAM_GROUP_OBJECT.value),
                    ],
                },
            },
        ],
    },
]

TEST_SYSTEM_ADMIN_DATA = {
    "name": "System Administrator",
    "object_class": "user",
    "is_system": True,
    "organizationalPerson": {
        "sam_account_name": "system_admin",
        "user_principal_name": "system_admin",
        "mail": "system_admin@mail.com",
        "display_name": "system_admin",
        "password": "password",
        "groups": [DOMAIN_ADMIN_GROUP_NAME],
    },
    "attributes": {
        "objectClass": [
            "top",
            "person",
            "organizationalPerson",
            "posixAccount",
            "inetOrgPerson",
            "shadowAccount",
        ],
        "posixEmail": ["abctest@mail.com"],
        "attr_with_bvalue": [b"any"],
        "userAccountControl": [str(UserAccountControlFlag.NORMAL_ACCOUNT)],
    },
}
