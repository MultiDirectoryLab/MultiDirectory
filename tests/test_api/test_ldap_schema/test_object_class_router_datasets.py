"""Datasets for testing the ObjectClassRouter."""

from fastapi import status

test_create_one_object_class_dataset = [
    {
        "attribute_types": [
            {
                "oid": "1.2.3.4",
                "name": "testAttributeType1",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testAttributeType2",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5.6",
                "name": "testAttributeType3",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
        ],
        "object_class": {
            "oid": "1.2.3.4",
            "name": "testObjectClass1",
            "superior": "testSuperior",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_types_must": [
                "testAttributeType1",
                "testAttributeType2",
            ],
            "attribute_types_may": ["testAttributeType3"],
        },
    },
    {
        "attribute_types": [],
        "object_class": {
            "oid": "1.2.3.4",
            "name": "testObjectClass2",
            "superior": "testSuperior",
            "kind": "ABSTRACT",
            "is_system": False,
            "attribute_types_must": [],
            "attribute_types_may": [],
        },
    },
]


test_modify_one_object_class_dataset = [
    {
        "attribute_types": [],
        "object_class_data": {
            "oid": "1.2.3.4",
            "name": "modifiedObjectClass",
            "superior": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_types_must": [],
            "attribute_types_may": [],
        },
        "new_statement": {
            "superior": None,
            "kind": "ABSTRACT",
            "is_system": False,
            "attribute_types_must": [],
            "attribute_types_may": [],
        },
    },
    {
        "attribute_types": [
            {
                "oid": "1.2.3.4",
                "name": "testAttributeType1",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
        ],
        "object_class_data": {
            "oid": "1.2.3.4",
            "name": "modifiedObjectClass",
            "superior": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_types_must": ["testAttributeType1"],
            "attribute_types_may": [],
        },
        "new_statement": {
            "superior": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_types_must": [],
            "attribute_types_may": ["testAttributeType1"],
        },
    },
    {
        "attribute_types": [
            {
                "oid": "1.2.3.4",
                "name": "testAttributeType1",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testAttributeType2",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
        ],
        "object_class_data": {
            "oid": "1.2.3.4",
            "name": "modifiedObjectClass",
            "superior": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_types_must": ["testAttributeType1"],
            "attribute_types_may": [],
        },
        "new_statement": {
            "superior": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_types_must": [
                "testAttributeType1",
                "testAttributeType2",
            ],
            "attribute_types_may": [],
        },
    },
    {
        "attribute_types": [
            {
                "oid": "1.2.3.4",
                "name": "testAttributeType1",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testAttributeType2",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5.6",
                "name": "testAttributeType3",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
        ],
        "object_class_data": {
            "oid": "1.2.3.4",
            "name": "modifiedObjectClass",
            "superior": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_types_must": ["testAttributeType1"],
            "attribute_types_may": ["testAttributeType2"],
        },
        "new_statement": {
            "superior": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_types_must": [],
            "attribute_types_may": ["testAttributeType3"],
        },
    },
]
test_delete_bulk_object_classes_dataset = [
    {
        "object_class_datas": [],
        "object_classes_deleted": [],
        "status_code": status.HTTP_400_BAD_REQUEST,
    },
    {
        "object_class_datas": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior": "top",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": [],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass2",
                "superior": "top",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": [],
            },
        ],
        "object_classes_deleted": ["testObjectClass1", "testObjectClass2"],
        "status_code": status.HTTP_200_OK,
    },
    {
        "object_class_datas": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior": "top",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_types_must": [],
                "attribute_types_may": [],
            },
        ],
        "object_classes_deleted": [
            "testObjectClass1",
            "testObjectClass2",
            "testObjectClass3",
            "testObjectClass4",
        ],
        "status_code": status.HTTP_200_OK,
    },
]
