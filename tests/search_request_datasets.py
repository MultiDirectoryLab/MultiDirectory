"""Datasets for test Search Requests.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

from ldap_protocol.objects import UserAccountControlFlag

test_search_filter_account_expires_dataset = [
    "(accountExpires=*)",
    "(accountExpires=134006890408650000)",
    "(accountExpires<=134006890408650000)",
    "(accountExpires>=134006890408650000)",
    "(accountExpires>=0)",  # NOTE: mindate
    "(accountExpires<=2650465908000000000)",  # NOTE: maxdate is December 30, 9999  # noqa: E501
]

test_search_by_rule_anr_dataset = [
    # with split by space
    {"filter": "(anr=Joh Leno)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},  # noqa: E501
    {"filter": "(anr=Lenon John)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},  # noqa: E501
    {"filter": "(anr=John Lenon)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},  # noqa: E501
    {"filter": "(anr=john lenon)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},  # noqa: E501
    {"filter": "(anr==Lenon John)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},  # noqa: E501
    # without split by space
    {"filter": "(anr=user0)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(anr=user0*)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(anr>=user0)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(anr<=user0)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(anr~=user0)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(anr==user0)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(anr==user0*)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(aNR=user0*)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(anr=uSEr0*)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(anr=domain admins)", "objects": ["cn=domain admins,cn=groups,dc=md,dc=test"]},  # noqa: E501
    {"filter": "(anr=user_admin_3@mail.com)", "objects": ["cn=user_admin_3,ou=test_bit_rules,dc=md,dc=test"]},  # noqa: E501
    {
        "filter": "(anr=user_admin_*)",
        "objects": [
            "cn=user_admin,cn=users,dc=md,dc=test",
            "cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
            "cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
            "cn=user_admin_3,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
]  # fmt: skip

test_search_by_rule_bit_and_dataset = [
    {
        "filter": f"(useraccountcontrol:1.2.840.113556.1.4.803:={UserAccountControlFlag.NORMAL_ACCOUNT})",  # noqa: E501
        "objects": [
            "cn=user0,cn=users,dc=md,dc=test",
            "cn=user_admin,cn=users,dc=md,dc=test",
            "cn=user_non_admin,cn=users,dc=md,dc=test",
            "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test",
            "cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
            "cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    {
        "filter": f"(userAccountControl:1.2.840.113556.1.4.803:={
            UserAccountControlFlag.NOT_DELEGATED
            + UserAccountControlFlag.NORMAL_ACCOUNT
        })",
        "objects": [
            "cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
            "cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    {
        "filter": f"(useraccountcontrol:1.2.840.113556.1.4.803:={
            UserAccountControlFlag.NOT_DELEGATED
            + UserAccountControlFlag.NORMAL_ACCOUNT
            + UserAccountControlFlag.LOCKOUT
            + UserAccountControlFlag.ACCOUNTDISABLE
        })",
        "objects": [
            "cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    {
        "filter": f"(!(userAccountControl:1.2.840.113556.1.4.803:={UserAccountControlFlag.ACCOUNTDISABLE}))",  # noqa: E501
        "objects": [
            "cn=user0,cn=users,dc=md,dc=test",
            "cn=user_admin,cn=users,dc=md,dc=test",
            "cn=user_non_admin,cn=users,dc=md,dc=test",
            "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test",
            "cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    {
        "filter": "(groupType:1.2.840.113556.1.4.803:=2147483648)",
        "objects": [],
    },
]

test_search_by_rule_bit_or_dataset = [
    {
        "filter": f"(useraccountcontrol:1.2.840.113556.1.4.804:={
            UserAccountControlFlag.ACCOUNTDISABLE
            + UserAccountControlFlag.NORMAL_ACCOUNT
        })",
        "objects": [
            "cn=user0,cn=users,dc=md,dc=test",
            "cn=user_admin,cn=users,dc=md,dc=test",
            "cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
            "cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
            "cn=user_admin_3,ou=test_bit_rules,dc=md,dc=test",
            "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test",
            "cn=user_non_admin,cn=users,dc=md,dc=test",
        ],
    },
    {
        "filter": f"(userAccountControl:1.2.840.113556.1.4.804:={UserAccountControlFlag.ACCOUNTDISABLE})",  # noqa: E501
        "objects": [
            "cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
            "cn=user_admin_3,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    {
        "filter": f"(!(userAccountControl:1.2.840.113556.1.4.804:={UserAccountControlFlag.ACCOUNTDISABLE}))",  # noqa: E501
        "objects": [
            "cn=user0,cn=users,dc=md,dc=test",
            "cn=user_admin,cn=users,dc=md,dc=test",
            "cn=user_non_admin,cn=users,dc=md,dc=test",
            "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test",
            "cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    {
        "filter": "(groupType:1.2.840.113556.1.4.804:=2147483648)",
        "objects": [],
    },
]
