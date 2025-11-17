"""Datasets for test LDAP search.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

# TODO мб объединить два файла с тест данными?
from ldap_protocol.objects import UserAccountControlFlag

test_ldap_search_filter_anr_dataset = [
    {"filter": "(anr=user0*)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(aNR=user0*)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {"filter": "(anr=uSEr0*)", "objects": ["cn=user0,cn=users,dc=md,dc=test"]},
    {
        "filter": "(anr=user_admin_*)",
        "objects": [
            "cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
            "cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
            "cn=user_admin_3,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    # {  # TODO почему это не работает?
    #     "filter": "(anr=user_admin_3@mail.c*)",
    #     "objects": ["cn=user_admin_3,ou=test_bit_rules,dc=md,dc=test"],
    # },
]

test_ldap_search_by_rule_bit_and_dataset = [
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

test_ldap_search_by_rule_bit_or_dataset = [
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
