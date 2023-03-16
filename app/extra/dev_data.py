DATA = [  # noqa
    {
        "name": "groups",
        "object_class": "group",
        "attributes": {
            "objectClass": ["top"],
            'groupType': ['-2147483646'],
            'instanceType': ['4'],
            'objectGUID': ['{9aac5c3d-689f-4557-806a-f123ed6bb230}'],
            'objectSid': ['S-1-5-21-625588008-872595822-1771925161-6007'],
            'sAMAccountName': ['groups'],
            'sAMAccountType': ['268435456'],
        },
        "children": [
            {"name": "administrators", "object_class": "group",
                "attributes": {"objectClass": ["top"]}},
            {"name": "committers", "object_class": "group",
                "attributes": {"objectClass": ["top"]}},
            {"name": "operators", "object_class": "group",
                "attributes": {"objectClass": ["top"]}},
            {"name": "guests", "object_class": "group", 'groups': [
                "operators", 'committers']},
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
                    "top", "person", "organizationalPerson"]},
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
                    "top", "person", "organizationalPerson"]},
            },
        ],
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
                    "groups": ["operators", "guests"]
                },
                "attributes": {"objectClass": [
                    "top", "person", "organizationalPerson"]},
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
                    "groups": ["guests"]
                },
                "attributes": {"objectClass": [
                    "top", "person", "organizationalPerson"]},
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
                            "top", "person", "organizationalPerson"]},
                    },
                ],
            },
        ],
    },
]