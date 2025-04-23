"""Datasets for test flat LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.ldap_codes import LDAPCodes

_base1: dict = {
    "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
    "single_value": True,
    "no_user_modification": False,
    "is_system": False,
}
test_get_attribute_type_names_by_object_class_names_dataset = [
    {  # NOTE: test empty attr names
        "attribute_types": [],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": [],
            }
        ],
        "object_class_names": ["testObjectClass1"],
        "result": {
            "must": set(),
            "may": set(),
        },
    },
    {  # NOTE: test merge must attrs by superior with first depth
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1},
            {"oid": "1.2.3.4.5", "name": "testAttributeType2", **_base1},
            {"oid": "1.2.3.4.5.6", "name": "testAttributeType3", **_base1},
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": ["testAttributeType1"],
                "attribute_types_may": ["testAttributeType3"],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "superior_name": "testObjectClass2",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": ["testAttributeType2"],
                "attribute_types_may": [],
            },
        ],
        "object_class_names": ["testObjectClass1"],
        "result": {
            "must": {"testAttributeType1", "testAttributeType2"},
            "may": {"testAttributeType3"},
        },
    },
    {  # NOTE: test merge may attrs by superior with first depth
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1},
            {"oid": "1.2.3.4.5", "name": "testAttributeType2", **_base1},
            {"oid": "1.2.3.4.5.6", "name": "testAttributeType3", **_base1},
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": ["testAttributeType1"],
                "attribute_types_may": ["testAttributeType3"],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "superior_name": "testObjectClass2",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": ["testAttributeType2"],
            },
        ],
        "object_class_names": ["testObjectClass1"],
        "result": {
            "must": {"testAttributeType1"},
            "may": {"testAttributeType2", "testAttributeType3"},
        },
    },
    {  # NOTE: test merge attrs by superior with second depth
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1},
            {"oid": "1.2.3.4.5", "name": "testAttributeType2", **_base1},
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass3",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": ["testAttributeType1"],
                "attribute_types_may": ["testAttributeType2"],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass2",
                "superior_name": "testObjectClass3",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": [],
            },
            {
                "oid": "1.2.3.4.5.6",
                "name": "testObjectClass1",
                "superior_name": "testObjectClass2",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": [],
            },
        ],
        "object_class_names": ["testObjectClass1"],
        "result": {
            "must": {"testAttributeType1"},
            "may": {"testAttributeType2"},
        },
    },
    {  # NOTE: test merge attrs by neighbours
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1},
            {"oid": "1.2.3.4.5", "name": "testAttributeType2", **_base1},
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": ["testAttributeType1"],
                "attribute_types_may": [],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": ["testAttributeType2"],
            },
        ],
        "object_class_names": ["testObjectClass1", "testObjectClass2"],
        "result": {
            "must": {"testAttributeType1"},
            "may": {"testAttributeType2"},
        },
    },
    {  # NOTE: test that must attrs is more important than may attrs for neighbours  # noqa: E501
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1},
            {"oid": "1.2.3.4.5", "name": "testAttributeType2", **_base1},
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": [
                    "testAttributeType1",
                    "testAttributeType2",
                ],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [
                    "testAttributeType1",
                    "testAttributeType2",
                ],
                "attribute_types_may": [],
            },
        ],
        "object_class_names": ["testObjectClass1", "testObjectClass2"],
        "result": {
            "must": {"testAttributeType1", "testAttributeType2"},
            "may": set(),
        },
    },
    {  # NOTE: test that must attrs is more important than may attrs if has superior  # noqa: E501
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1},
            {"oid": "1.2.3.4.5", "name": "testAttributeType2", **_base1},
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": [
                    "testAttributeType1",
                    "testAttributeType2",
                ],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "superior_name": "testObjectClass2",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [
                    "testAttributeType1",
                    "testAttributeType2",
                ],
                "attribute_types_may": [],
            },
        ],
        "object_class_names": ["testObjectClass1"],
        "result": {
            "must": {"testAttributeType1", "testAttributeType2"},
            "may": set(),
        },
    },
]

_base2: dict = {
    "superior_name": None,
    "is_system": False,
    "attribute_types_must": [],
    "attribute_types_may": [],
}
test_validate_chunck_object_classes_by_ldap_schema_dataset = [
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "kind": "STRUCTURAL",
                **_base2,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "kind": "STRUCTURAL",
                **_base2,
            },
        ],
        "object_class_names": ["testObjectClass1", "testObjectClass2"],
        "structural": {"testObjectClass1", "testObjectClass2"},
    },
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "kind": "AUXILIARY",
                **_base2,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "kind": "STRUCTURAL",
                **_base2,
            },
        ],
        "object_class_names": ["testObjectClass1", "testObjectClass2"],
        "structural": {"testObjectClass1"},
    },
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "kind": "ABSTRACT",
                **_base2,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "kind": "STRUCTURAL",
                **_base2,
            },
        ],
        "object_class_names": ["testObjectClass1", "testObjectClass2"],
        "structural": {"testObjectClass1"},
    },
]

test_validate_chunck_object_classes_by_ldap_schema_error_dataset = [
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "kind": "ABSTRACT",
                **_base2,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "kind": "ABSTRACT",
                **_base2,
            },
        ],
        "object_class_names": ["testObjectClass1", "testObjectClass2"],
        "error": LDAPCodes.OBJECT_CLASS_VIOLATION,
    },
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "kind": "AUXILIARY",
                **_base2,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "kind": "AUXILIARY",
                **_base2,
            },
        ],
        "object_class_names": ["testObjectClass1", "testObjectClass2"],
        "error": LDAPCodes.OBJECT_CLASS_VIOLATION,
    },
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass2",
                "kind": "ABSTRACT",
                **_base2,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass1",
                "kind": "AUXILIARY",
                **_base2,
            },
        ],
        "object_class_names": ["testObjectClass1", "testObjectClass2"],
        "error": LDAPCodes.OBJECT_CLASS_VIOLATION,
    },
    {
        "object_classes": [],
        "object_class_names": [],
        "error": LDAPCodes.OBJECT_CLASS_VIOLATION,
    },
]

test_validate_attributes_by_ldap_schema_dataset = [
    {
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1}
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": ["testAttributeType1"],
                "attribute_types_may": [],
            },
        ],
        "object_class_names": ["testObjectClass1"],
        "attributes": [("testAttributeType1", ["val1"])],
        "correct_attributes": {"testAttributeType1"},
        "useless_attributes": set(),
    },
    {
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1},
            {"oid": "1.2.3.4.5", "name": "testAttributeType2", **_base1},
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": ["testAttributeType1"],
                "attribute_types_may": [],
            },
        ],
        "object_class_names": ["testObjectClass1"],
        "attributes": [
            ("testAttributeType1", ["val1"]),
            ("testAttributeType2", ["val2"]),
        ],
        "correct_attributes": {"testAttributeType1"},
        "useless_attributes": {"testAttributeType2"},
    },
]

test_validate_attributes_by_ldap_schema_error_dataset = [
    {
        "attribute_types": [],
        "object_classes": [],
        "attributes": [],
        "object_class_names": ["testObjectClass1"],
        "error": LDAPCodes.NO_SUCH_ATTRIBUTE,
    },
    {
        "attribute_types": [],
        "object_classes": [],
        "attributes": [("testAttributeType1", ["val1"])],
        "object_class_names": [],
        "error": LDAPCodes.OBJECT_CLASS_VIOLATION,
    },
    {
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1},
            {"oid": "1.2.3.4.5", "name": "testAttributeType2", **_base1},
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": ["testAttributeType1"],
                "attribute_types_may": ["testAttributeType2"],
            },
        ],
        "object_class_names": ["testObjectClass1"],
        "attributes": [
            ("testAttributeType1", []),
            ("testAttributeType2", ["val2"]),
        ],
        "error": LDAPCodes.INVALID_ATTRIBUTE_SYNTAX,
    },
    {
        "attribute_types": [
            {"oid": "1.2.3.4", "name": "testAttributeType1", **_base1},
            {"oid": "1.2.3.4.5", "name": "testAttributeType2", **_base1},
        ],
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": ["testAttributeType1"],
                "attribute_types_may": ["testAttributeType2"],
            },
        ],
        "object_class_names": ["testObjectClass1"],
        "attributes": [("testAttributeType2", ["val2"])],
        "error": LDAPCodes.OBJECT_CLASS_VIOLATION,
    },
]
