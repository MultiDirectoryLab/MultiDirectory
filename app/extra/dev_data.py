"""Data variables."""

group_attrs = {
    "objectClass": ["top"],
    'groupType': ['-2147483646'],
    'instanceType': ['4'],
    'sAMAccountName': ['groups'],
    'sAMAccountType': ['268435456'],
}


DATA = [  # noqa
    {
        "name": "main",
        "object_class": "builtinDomain",
        "attributes": {
            "objectClass": ["top"],
            'sAMAccountName': ['main'],
        },
        "children": [
            {
                "name": "administrators",
                "object_class": "group",
                "attributes": group_attrs | {
                    'sAMAccountName': ['administrators']},
            },
            {
                "name": "committers",
                "object_class": "group",
                "attributes": group_attrs | {'sAMAccountName': ['committers']},
            },
            {
                "name": "operators",
                "object_class": "group",
                "attributes": group_attrs | {'sAMAccountName': ['operators']},
            },
            {
                "name": "guests",
                "object_class": "group",
                "attributes": group_attrs | {'sAMAccountName': ['guests']},
                'groups': ["operators", 'committers'],
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
                    "groups": ['administrators', 'operators'],
                },
                "attributes": {"objectClass": [
                    "top", "person",
                    "organizationalPerson", "posixAccount"]},
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
                    "groups": ['administrators', 'operators']
                },
                "attributes": {"objectClass": [
                    "top", "person",
                    "organizationalPerson", "posixAccount"]},
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
            "groups": ['administrators', 'operators'],
        },
        "attributes": {"objectClass": [
            "top", "person",
            "organizationalPerson", "posixAccount"]},
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
                        "top", "person",
                        "organizationalPerson", "posixAccount"],
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
                "attributes": {"objectClass": [
                    "top", "person",
                    "organizationalPerson", "posixAccount"]},
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
                        "object_class": "user", "organizationalPerson": {
                            "sam_accout_name": "username5",
                            "user_principal_name": "username5@multifactor.dev",
                            "mail": "username5@multifactor.dev",
                            "display_name": "User 5",
                            "password": "password",
                        },
                        "attributes": {"objectClass": [
                            "top", "person",
                            "organizationalPerson", "posixAccount"]},
                    },
                ],
            },
        ],
    },
]


TEST_DATA = [  # noqa
    {
        "name": "groups",
        "object_class": "container",
        "attributes": {
            "objectClass": ["top"],
            'sAMAccountName': ['groups'],
        },
        "children": [
            {
                "name": "domain admins",
                "object_class": "group",
                "attributes": {
                    "objectClass": ["top"],
                    'groupType': ['-2147483646'],
                    'instanceType': ['4'],
                    'sAMAccountName': ['domain admins'],
                    'sAMAccountType': ['268435456'],
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
                    "groups": ['domain admins'],
                },
                "attributes": {"objectClass": [
                    "top", "person",
                    "organizationalPerson", "posixAccount"]},
            },
        ],
    },
]
