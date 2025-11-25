"""Datasets for test attribute type router."""

from fastapi import status

from api.ldap_schema.schema import AttributeTypeSchema

test_modify_one_attribute_type_dataset = [
    {
        "attribute_type_name": "testAttributeType0",
        "attribute_type_schema": AttributeTypeSchema(
            oid="1.2.3.4",
            name="testAttributeType0",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=False,
            no_user_modification=False,
            is_system=False,
            is_included_anr=False,
        ),
        "attribute_type_changes": {
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": True,
            "no_user_modification": False,
            "is_included_anr": False,
        },
        "status_code": status.HTTP_200_OK,
    },
    {
        "attribute_type_name": "testAttributeType1_notvalidname",
        "attribute_type_schema": AttributeTypeSchema(
            oid="1.2.3.4",
            name="testAttributeType1",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
            no_user_modification=False,
            is_system=False,
            is_included_anr=False,
        ),
        "attribute_type_changes": {
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": True,
            "no_user_modification": False,
            "is_included_anr": False,
        },
        "status_code": status.HTTP_404_NOT_FOUND,
    },
    {
        "attribute_type_name": "testAttributeType2",
        "attribute_type_schema": AttributeTypeSchema(
            oid="1.2.3.4",
            name="testAttributeType2",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=False,
            no_user_modification=False,
            is_system=True,
            is_included_anr=False,
        ),
        "attribute_type_changes": {
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": True,
            "no_user_modification": False,
            "is_included_anr": False,
        },
        "status_code": status.HTTP_200_OK,
    },
]

test_delete_bulk_attribute_types_dataset = [
    {
        "attribute_type_schemas": [
            AttributeTypeSchema(
                oid="1.2.3.4",
                name="testAttributeType1",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                single_value=True,
                no_user_modification=False,
                is_system=False,
                is_included_anr=False,
            ),
            AttributeTypeSchema(
                oid="1.2.3.4.5",
                name="testAttributeType2",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                single_value=True,
                no_user_modification=False,
                is_system=False,
                is_included_anr=False,
            ),
        ],
        "attribute_types_deleted": [
            "testAttributeType1",
            "testAttributeType2",
        ],
        "status_code": status.HTTP_200_OK,
    },
    {
        "attribute_type_schemas": [
            AttributeTypeSchema(
                oid="1.2.3.4",
                name="testAttributeType1",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                single_value=True,
                no_user_modification=False,
                is_system=False,
                is_included_anr=False,
            ),
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
        "attribute_type_schemas": [],
        "attribute_types_deleted": [],
        "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
    },
]
