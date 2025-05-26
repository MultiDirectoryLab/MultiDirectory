"""Data variables.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

group_attrs = {
    "objectClass": ["top"],
    "groupType": ["-2147483646"],
    "instanceType": ["4"],
    "sAMAccountName": ["groups"],
    "sAMAccountType": ["268435456"],
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
        "object_class": "organizationalUnit",
        "attributes": {"objectClass": ["top", "container"]},
        "children": [
            {
                "name": "user 1",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_accout_name": "username1",
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
                    "sam_accout_name": "username2",
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
            "sam_accout_name": "username0",
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
        "name": "users",
        "object_class": "organizationalUnit",
        "attributes": {"objectClass": ["top", "container"]},
        "children": [
            {
                "name": "user 3",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_accout_name": "username3",
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
                    "sam_accout_name": "username4",
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
        "object_class": "organizationalUnit",
        "attributes": {"objectClass": ["top", "container"]},
        "children": [
            {
                "name": "service accounts",
                "object_class": "organizationalUnit",
                "attributes": {"objectClass": ["top", "container"]},
                "children": [
                    {
                        "name": "user 5",
                        "object_class": "user",
                        "organizationalPerson": {
                            "sam_accout_name": "username5",
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
                    "objectClass": ["top"],
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
                    "objectClass": ["top"],
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
                    "objectClass": ["top"],
                    "groupType": ["-2147483646"],
                    "instanceType": ["4"],
                    "sAMAccountName": ["domain users"],
                    "sAMAccountType": ["268435456"],
                },
            },
        ],
    },
    {
        "name": "users",
        "object_class": "organizationalUnit",
        "attributes": {"objectClass": ["top", "container"]},
        "children": [
            {
                "name": "user0",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_accout_name": "user0",
                    "user_principal_name": "user0",
                    "mail": "user0@mail.com",
                    "display_name": "user0",
                    "password": "password",
                    "groups": ["domain admins"],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                    ],
                    "posixEmail": ["abctest@mail.com"],
                    "attr_with_bvalue": [b"any"],
                    "userAccountControl": ["512"],
                    "description": ["123 desc"],
                },
            },
            {
                "name": "user_non_admin",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_accout_name": "user_non_admin",
                    "user_principal_name": "user_non_admin",
                    "mail": "user_non_admin@mail.com",
                    "display_name": "user_non_admin",
                    "password": "password",
                    "groups": ["domain users"],
                },
                "attributes": {
                    "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "posixAccount",
                        "inetOrgPerson",
                    ],
                    "posixEmail": ["abctest@mail.com"],
                    "attr_with_bvalue": [b"any"],
                    "userAccountControl": ["512"],
                },
            },
            {
                "name": "russia",
                "object_class": "organizationalUnit",
                "attributes": {
                    "objectClass": ["top"],
                    "sAMAccountName": ["groups"],
                },
                "children": [
                    {
                        "name": "moscow",
                        "object_class": "organizationalUnit",
                        "attributes": {
                            "objectClass": ["top"],
                            "sAMAccountName": ["groups"],
                        },
                        "children": [
                            {
                                "name": "user1",
                                "object_class": "user",
                                "organizationalPerson": {
                                    "sam_accout_name": "user1",
                                    "user_principal_name": "user1",
                                    "mail": "user1@mail.com",
                                    "display_name": "user1",
                                    "password": "password",
                                    "groups": ["developers"],
                                },
                                "attributes": {
                                    "objectClass": [
                                        "top",
                                        "person",
                                        "organizationalPerson",
                                        "posixAccount",
                                        "inetOrgPerson",
                                    ],
                                    "posixEmail": ["user1@mail.com"],
                                    "userAccountControl": ["512"],
                                },
                            },
                        ],
                    },
                ],
            },
        ],
    },
]
