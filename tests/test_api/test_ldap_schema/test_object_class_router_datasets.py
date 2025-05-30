"""Datasets for testing the object class router."""

from fastapi import status

test_create_one_object_class_dataset = [
    {
        "attribute_types": [
            {
                "oid": "1.2.3.4",
                "name": "testAttributeType1",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testAttributeType2",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5.6",
                "name": "testAttributeType3",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
        ],
        "object_class": {
            "oid": "1.2.3.4",
            "name": "testObjectClass1",
            "superior_name": None,
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_type_names_must": [
                "testAttributeType1",
                "testAttributeType2",
            ],
            "attribute_type_names_may": ["testAttributeType3"],
        },
    },
    {
        "attribute_types": [],
        "object_class": {
            "oid": "1.2.3.4",
            "name": "testObjectClass2",
            "superior_name": None,
            "kind": "ABSTRACT",
            "is_system": False,
            "attribute_type_names_must": [],
            "attribute_type_names_may": [],
        },
    },
    {
        "attribute_types": [],
        "object_class": {
            "oid": "1.2.3.4",
            "name": "testObjectClass3",
            "superior_name": "top",
            "kind": "ABSTRACT",
            "is_system": False,
            "attribute_type_names_must": [],
            "attribute_type_names_may": [],
        },
    },
]


test_modify_one_object_class_dataset = [
    {
        "attribute_types": [],
        "object_class_data": {
            "oid": "1.2.3.4",
            "name": "modifiedObjectClass",
            "superior_name": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_type_names_must": [],
            "attribute_type_names_may": [],
        },
        "new_statement": {
            "attribute_type_names_must": [],
            "attribute_type_names_may": [],
        },
    },
    {
        "attribute_types": [
            {
                "oid": "1.2.3.4",
                "name": "testAttributeType1",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
        ],
        "object_class_data": {
            "oid": "1.2.3.4",
            "name": "modifiedObjectClass",
            "superior_name": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_type_names_must": ["testAttributeType1"],
            "attribute_type_names_may": [],
        },
        "new_statement": {
            "attribute_type_names_must": [],
            "attribute_type_names_may": ["testAttributeType1"],
        },
    },
    {
        "attribute_types": [
            {
                "oid": "1.2.3.4",
                "name": "testAttributeType1",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testAttributeType2",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
        ],
        "object_class_data": {
            "oid": "1.2.3.4",
            "name": "modifiedObjectClass",
            "superior_name": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_type_names_must": ["testAttributeType1"],
            "attribute_type_names_may": [],
        },
        "new_statement": {
            "attribute_type_names_must": [
                "testAttributeType1",
                "testAttributeType2",
            ],
            "attribute_type_names_may": [],
        },
    },
    {
        "attribute_types": [
            {
                "oid": "1.2.3.4",
                "name": "testAttributeType1",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testAttributeType2",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
            {
                "oid": "1.2.3.4.5.6",
                "name": "testAttributeType3",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
        ],
        "object_class_data": {
            "oid": "1.2.3.4",
            "name": "modifiedObjectClass",
            "superior_name": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_type_names_must": ["testAttributeType1"],
            "attribute_type_names_may": ["testAttributeType2"],
        },
        "new_statement": {
            "kind": "STRUCTURAL",
            "attribute_type_names_must": [],
            "attribute_type_names_may": ["testAttributeType3"],
        },
    },
]


test_delete_bulk_object_classes_dataset = [
    {
        "object_class_datas": [],
        "object_classes_deleted": [],
        "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
    },
    {
        "object_class_datas": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior_name": "top",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass2",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
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
                "superior_name": "top",
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
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

test_delete_bulk_used_object_classes_dataset = [
    {
        "object_class_data": {
            "oid": "1.2.3.4",
            "name": "testObjectClass1",
            "superior_name": "top",
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_type_names_must": [],
            "attribute_type_names_may": [],
        },
        "entity_type_data": {
            "name": "testEntityType1",
            "is_system": False,
            "object_class_names": ["testObjectClass1"],
        },
        "object_class_deleted": "testObjectClass1",
    },
]
