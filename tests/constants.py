"""Data variables for tests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.objects import UserAccountControlFlag

TEST_DATA = [
    {
        "name": "groups",
        "object_class": "container",
        "attributes": {
            "objectClass": ["top"],
            "sAMAccountName": ["groups"],
        },
        "children": [
            {
                "name": "domain admins",
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["domain admins"],
                    "sAMAccountType": ["268435456"],
                },
            },
            {
                "name": "developers",
                "object_class": "group",
                "groups": ["domain admins"],
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["developers"],
                    "sAMAccountType": ["268435456"],
                },
            },
            {
                "name": "domain users",
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["domain users"],
                    "sAMAccountType": ["268435456"],
                },
            },
            {
                "name": "domain computers",
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["domain computers"],
                    "sAMAccountType": ["268435456"],
                },
            },
        ],
    },
    {
        "name": "users",
        "object_class": "container",
        "attributes": {"objectClass": ["top"]},
        "children": [
            {
                "name": "user0",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_account_name": "user0",
                    "user_principal_name": "user0",
                    "mail": "user0@mail.com",
                    "display_name": "user0",
                    "password": "password",
                    "groups": [
                        "domain admins",
                    ],
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
                "organizationalPerson": {
                    "sam_account_name": "user_admin",
                    "user_principal_name": "user_admin",
                    "mail": "user_admin@mail.com",
                    "display_name": "user_admin",
                    "password": "password",
                    "groups": [
                        "domain admins",
                    ],
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
                "organizationalPerson": {
                    "sam_account_name": "user_admin_for_roles",
                    "user_principal_name": "user_admin_for_roles",
                    "mail": "user_admin_for_roles@mail.com",
                    "display_name": "user_admin_for_roles",
                    "password": "password",
                    "groups": [
                        "domain admins",
                    ],
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
                "organizationalPerson": {
                    "sam_account_name": "user_non_admin",
                    "user_principal_name": "user_non_admin",
                    "mail": "user_non_admin@mail.com",
                    "display_name": "user_non_admin",
                    "password": "password",
                    "groups": ["domain users"],
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
                "attributes": {
                    "objectClass": ["top"],
                    "sAMAccountName": ["groups"],
                },
                "children": [
                    {
                        "name": "moscow",
                        "object_class": "container",
                        "attributes": {
                            "objectClass": ["top"],
                            "sAMAccountName": ["groups"],
                        },
                        "children": [
                            {
                                "name": "user1",
                                "object_class": "user",
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
        "attributes": {"objectClass": ["top", "container"]},
        "children": [
            {
                "name": "user_admin_1",
                "object_class": "user",
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
        "attributes": {
            "objectClass": ["top", "container"],
            "sAMAccountName": ["testModifyDn1"],
        },
        "children": [
            {
                "name": "testModifyDn2",
                "object_class": "organizationalUnit",
                "attributes": {
                    "objectClass": ["top", "container"],
                    "sAMAccountName": ["testModifyDn2"],
                },
                "children": [
                    {
                        "name": "testGroup1",
                        "object_class": "group",
                        "attributes": {
                            "objectClass": ["top", "posixGroup"],
                            "groupType": ["-2147483646"],
                            "instanceType": ["4"],
                            "sAMAccountName": ["testGroup1"],
                            "sAMAccountType": ["268435456"],
                        },
                    },
                ],
            },
            {
                "name": "testGroup2",
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["testGroup2"],
                    "sAMAccountType": ["268435456"],
                },
            },
        ],
    },
    {
        "name": "testModifyDn3",
        "object_class": "organizationalUnit",
        "attributes": {
            "objectClass": ["top", "container"],
            "sAMAccountName": ["testModifyDn3"],
        },
        "children": [
            {
                "name": "testGroup3",
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top", "posixGroup"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["testGroup3"],
                    "sAMAccountType": ["268435456"],
                },
            },
        ],
    },
]
