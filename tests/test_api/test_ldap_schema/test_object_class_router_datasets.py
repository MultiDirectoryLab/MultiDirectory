"""Datasets for testing the ObjectClassRouter."""

from fastapi import status

test_create_one_object_class_dataset = [
    {
        "oid": "1.2.3.4",
        "name": "testObjectClass1",
        "superior": "top",
        "kind": "STRUCTURAL",
        "is_system": True,
        "attribute_types_must": [],
        "attribute_types_may": [],
    },
    {
        "oid": "1.2.3.4.5",
        "name": "testObjectClass2",
        "superior": "top",
        "kind": "STRUCTURAL",
        "is_system": True,
        "attribute_types_must": [],
        "attribute_types_may": [],
    },
]

test_delete_bulk_object_classes_dataset = [
    {
        "object_class_datas": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior": "top",
                "kind": "STRUCTURAL",
                "is_system": True,
                "attribute_types_must": [],
                "attribute_types_may": [],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass2",
                "superior": "top",
                "kind": "STRUCTURAL",
                "is_system": True,
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
                "is_system": True,
                "attribute_types_must": [],
                "attribute_types_may": [],
            },
        ],
        "object_classes_deleted": ["testObjectClass1", "testObjectClass2"],
        "status_code": status.HTTP_400_BAD_REQUEST,
    },
    {
        "object_class_datas": [],
        "object_classes_deleted": [],
        "status_code": status.HTTP_400_BAD_REQUEST,
    },
]
