"""Datasets for test LDAP search.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

from ldap_protocol.user_account_control import UserAccountControlFlag

test_ldap_search_by_rule_bit_and_dataset = [
    {
        "filter": f"(useraccountcontrol:1.2.840.113556.1.4.803:={UserAccountControlFlag.NORMAL_ACCOUNT})",  # noqa: E501
        "objects": [
            "dn: cn=user0,cn=users,dc=md,dc=test",
            "dn: cn=user_admin,cn=users,dc=md,dc=test",
            "dn: cn=user_non_admin,cn=users,dc=md,dc=test",
            "dn: cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test",
        ],
    },
    {
        "filter": f"(userAccountControl:1.2.840.113556.1.4.803:={
            UserAccountControlFlag.NOT_DELEGATED
            + UserAccountControlFlag.NORMAL_ACCOUNT
        })",
        "objects": [
            "dn: cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
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
            "dn: cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    {
        "filter": f"(!(userAccountControl:1.2.840.113556.1.4.803:={UserAccountControlFlag.ACCOUNTDISABLE}))",  # noqa: E501
        "objects": [
            "dn: cn=user0,cn=users,dc=md,dc=test",
            "dn: cn=user_admin,cn=users,dc=md,dc=test",
            "dn: cn=user_non_admin,cn=users,dc=md,dc=test",
            "dn: cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test",
            "dn: cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
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
            "dn: cn=user0,cn=users,dc=md,dc=test",
            "dn: cn=user_admin,cn=users,dc=md,dc=test",
            "dn: cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
            "dn: cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
            "dn: cn=user_admin_3,ou=test_bit_rules,dc=md,dc=test",
            "dn: cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test",
            "dn: cn=user_non_admin,cn=users,dc=md,dc=test",
        ],
    },
    {
        "filter": f"(userAccountControl:1.2.840.113556.1.4.804:={UserAccountControlFlag.ACCOUNTDISABLE})",  # noqa: E501
        "objects": [
            "dn: cn=user_admin_1,ou=test_bit_rules,dc=md,dc=test",
            "dn: cn=user_admin_3,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    {
        "filter": f"(!(userAccountControl:1.2.840.113556.1.4.804:={UserAccountControlFlag.ACCOUNTDISABLE}))",  # noqa: E501
        "objects": [
            "dn: cn=user0,cn=users,dc=md,dc=test",
            "dn: cn=user_admin,cn=users,dc=md,dc=test",
            "dn: cn=user_non_admin,cn=users,dc=md,dc=test",
            "dn: cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test",
            "dn: cn=user_admin_2,ou=test_bit_rules,dc=md,dc=test",
        ],
    },
    {
        "filter": "(groupType:1.2.840.113556.1.4.804:=2147483648)",
        "objects": [],
    },
]
