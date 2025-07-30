"""Datasets for testing the entity type router."""

test_create_one_entity_type_dataset = [
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass2",
                "superior_name": None,
                "kind": "ABSTRACT",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
            },
        ],
        "entity_type": {
            "name": "testEntityType1",
            "object_class_names": ["testObjectClass1", "testObjectClass2"],
            "is_system": False,
        },
    },
]

test_get_list_entity_types_with_pagination_dataset = [
    {
        "object_class_names": [
            ("1.2.3.4.5", "objClassName1"),
            ("1.2.3.4.5.6", "objClassName2"),
            ("1.2.3.4.5.6.7", "objClassName3"),
        ],
        "entity_types": [
            {
                "name": "testEntityType1",
                "object_class_names": ["objClassName1"],
                "is_system": False,
            },
            {
                "name": "testEntityType2",
                "object_class_names": ["objClassName2"],
                "is_system": False,
            },
            {
                "name": "testEntityType3",
                "object_class_names": ["objClassName3"],
                "is_system": False,
            },
        ],
    },
]

test_modify_one_entity_type_dataset = [
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
            },
            {
                "oid": "1.2.3.4.5",
                "name": "testObjectClass2",
                "superior_name": None,
                "kind": "ABSTRACT",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
            },
        ],
        "entity_type": {
            "name": "testEntityType1",
            "object_class_names": ["testObjectClass1"],
            "is_system": False,
        },
        "new_statement": {
            "name": "testEntityType1",
            "object_class_names": ["testObjectClass2"],
        },
    },
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass3",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
            },
        ],
        "entity_type": {
            "name": "testEntityType1",
            "object_class_names": ["testObjectClass3"],
            "is_system": False,
        },
        "new_statement": {
            "name": "testEntityType2",
            "object_class_names": ["testObjectClass3"],
        },
    },
]

test_delete_bulk_entity_types_dataset = [
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "testObjectClass1",
                "superior_name": None,
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
        "entity_types": [
            {
                "name": "testEntityType1",
                "object_class_names": ["testObjectClass1"],
                "is_system": False,
            },
            {
                "name": "testEntityType2",
                "object_class_names": ["testObjectClass2"],
                "is_system": False,
            },
        ],
        "entity_type_names_deleted": ["testEntityType1", "testEntityType2"],
    },
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "objClassName1",
                "superior_name": None,
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
        "entity_types": [
            {
                "name": "testEntityType1",
                "object_class_names": ["objClassName1"],
                "is_system": False,
            },
            {
                "name": "testEntityType2",
                "object_class_names": ["testObjectClass2"],
                "is_system": False,
            },
        ],
        "entity_type_names_deleted": ["testEntityType1"],
    },
    {
        "object_classes": [
            {
                "oid": "1.2.3.4",
                "name": "objClassName1",
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
            },
        ],
        "entity_types": [
            {
                "name": "testEntityType1",
                "object_class_names": ["objClassName1"],
                "is_system": False,
            },
        ],
        "entity_type_names_deleted": [
            "testEntityType1",
            "testEntityType2",
            "testEntityType3",
        ],
    },
]
