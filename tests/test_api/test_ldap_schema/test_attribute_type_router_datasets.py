"""Datasets for test attribute type router."""

from fastapi import status

test_modify_one_attribute_type_dataset = [
    {
        "attribute_type_data": {
            "oid": "1.2.3.4",
            "name": "testAttributeType1",
            "syntax": "testSyntax",
            "single_value": True,
            "no_user_modification": False,
            "is_system": False,
        },
        "attribute_type_changes": {
            "oid": "1.2.3.4",
            "name": "testAttributeType1",
            "syntax": "testSyntax",
            "single_value": False,
            "no_user_modification": False,
            "is_system": False,
        },
        "status_code": status.HTTP_200_OK,
    },
    {
        "attribute_type_data": {
            "oid": "1.2.3.4",
            "name": "testAttributeType1",
            "syntax": "testSyntax",
            "single_value": True,
            "no_user_modification": False,
            "is_system": False,
        },
        "attribute_type_changes": {
            "oid": "1.2.3.5",
            "name": "testAttributeType1",
            "syntax": "testSyntax",
            "single_value": True,
            "no_user_modification": False,
            "is_system": False,
        },
        "status_code": status.HTTP_400_BAD_REQUEST,
    },
    {
        "attribute_type_data": {
            "oid": "1.2.3.4",
            "name": "testAttributeType1",
            "syntax": "testSyntax",
            "single_value": True,
            "no_user_modification": False,
            "is_system": False,
        },
        "attribute_type_changes": {
            "oid": "1.2.3.4",
            "name": "testAttributeType2",
            "syntax": "testSyntax",
            "single_value": True,
            "no_user_modification": False,
            "is_system": False,
        },
        "status_code": status.HTTP_400_BAD_REQUEST,
    },
]

test_delete_bulk_attribute_types_dataset = [
    {
        "attribute_type_datas": [
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
        "attribute_types_deleted": [
            "testAttributeType1",
            "testAttributeType2",
        ],
        "status_code": status.HTTP_200_OK,
    },
    {
        "attribute_type_datas": [
            {
                "oid": "1.2.3.4",
                "name": "testAttributeType1",
                "syntax": "testSyntax",
                "single_value": True,
                "no_user_modification": False,
                "is_system": False,
            },
        ],
        "attribute_types_deleted": [
            "testAttributeType1",
            "testAttributeType2",
            "testAttributeType3",
            "testAttributeType4",
        ],
        "status_code": status.HTTP_200_OK,
    },
    {
        "attribute_type_datas": [],
        "attribute_types_deleted": [],
        "status_code": status.HTTP_400_BAD_REQUEST,
    },
]
