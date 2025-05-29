"""Datasets for testing the entry router."""

test_create_one_entry_dataset = [
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
        "entry": {
            "name": "testEntry1",
            "object_class_names": ["testObjectClass1", "testObjectClass2"],
            "is_system": False,
        },
    },
]

test_get_list_entries_with_pagination_dataset = [
    {
        "object_class_names": [
            ("1.2.3.4.5", "objClassName1"),
            ("1.2.3.4.5.6", "objClassName2"),
            ("1.2.3.4.5.6.7", "objClassName3"),
        ],
        "entries": [
            {
                "name": "testEntry1",
                "object_class_names": ["objClassName1"],
                "is_system": False,
            },
            {
                "name": "testEntry2",
                "object_class_names": ["objClassName2"],
                "is_system": False,
            },
            {
                "name": "testEntry3",
                "object_class_names": ["objClassName3"],
                "is_system": False,
            },
        ],
    }
]

test_modify_one_entry_dataset = [
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
        "entry": {
            "name": "testEntry1",
            "object_class_names": ["testObjectClass1"],
            "is_system": False,
        },
        "new_statement": {
            "name": "testEntry1",
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
        "entry": {
            "name": "testEntry1",
            "object_class_names": ["testObjectClass3"],
            "is_system": False,
        },
        "new_statement": {
            "name": "testEntry2",
            "object_class_names": ["testObjectClass3"],
        },
    },
]

test_delete_bulk_entries_dataset = [
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
        "entry_datas": [
            {
                "name": "testEntry1",
                "object_class_names": ["testObjectClass1"],
                "is_system": False,
            },
            {
                "name": "testEntry2",
                "object_class_names": ["testObjectClass2"],
                "is_system": False,
            },
        ],
        "entries_deleted": ["testEntry1", "testEntry2"],
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
        "entry_datas": [
            {
                "name": "testEntry1",
                "object_class_names": ["objClassName1"],
                "is_system": False,
            },
            {
                "name": "testEntry2",
                "object_class_names": ["testObjectClass2"],
                "is_system": False,
            },
        ],
        "entries_deleted": ["testEntry1"],
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
        "entry_datas": [
            {
                "name": "testEntry1",
                "object_class_names": ["objClassName1"],
                "is_system": False,
            },
        ],
        "entries_deleted": ["testEntry1", "testEntry2", "testEntry3"],
    },
]
