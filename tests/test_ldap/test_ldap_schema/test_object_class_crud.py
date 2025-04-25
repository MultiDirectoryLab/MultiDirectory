"""Test Object Class CRUDs.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.attribute_type_crud import create_attribute_type
from ldap_protocol.ldap_schema.object_class_crud import (
    ObjectClassUpdateSchema,
    create_object_class,
    delete_object_classes_by_names,
    get_object_class_by_name,
    modify_object_class,
)


@pytest.mark.asyncio
async def test_create_object_class(session: AsyncSession) -> None:
    """Test create Object Class."""
    object_class_data: dict = {
        "oid": "1.2.3.4.5.6",
        "name": "customTestClass",
        "superior_name": None,
        "kind": "STRUCTURAL",
        "is_system": True,
        "attribute_types_must": [],
        "attribute_types_may": [],
    }
    object_class_name = object_class_data["name"]
    await create_object_class(session=session, **object_class_data)

    object_class = await get_object_class_by_name(
        object_class_name,
        session=session,
    )
    assert object_class is not None
    assert object_class.oid == object_class_data["oid"]
    assert object_class.name == object_class_data["name"]
    assert object_class.superior_name == object_class_data["superior_name"]
    assert object_class.kind == object_class_data["kind"]
    assert object_class.is_structural is True
    assert object_class.is_system == object_class_data["is_system"]
    assert set(object_class.attribute_types_must_display) == set(
        object_class_data["attribute_types_must"]
    )
    assert set(object_class.attribute_types_may_display) == set(
        object_class_data["attribute_types_may"]
    )


@pytest.mark.asyncio
async def test_create_object_class_errors1(session: AsyncSession) -> None:
    """Test ValuerError by create Object Class."""
    object_class_data: dict = {
        "oid": "1.2.3.4.5.6",
        "name": "customTestClass",
        "superior_name": None,
        "kind": "STRUCTURAAAAAL",
        "is_system": True,
        "attribute_types_must": [],
        "attribute_types_may": [],
    }
    object_class_kind = object_class_data["kind"]
    with pytest.raises(
        ValueError,
        match=f"Object class kind is not valid: {object_class_kind}.",
    ):
        await create_object_class(session=session, **object_class_data)


@pytest.mark.asyncio
async def test_create_object_class_errors2(session: AsyncSession) -> None:
    """Test ValuerError by create Object Class."""
    object_class_data: dict = {
        "oid": "1.2.3.4.5.6",
        "name": "customTestClass",
        "superior_name": "NotExistingSuperiorName",
        "kind": "STRUCTURAL",
        "is_system": True,
        "attribute_types_must": [],
        "attribute_types_may": [],
    }
    superior_name = object_class_data["superior_name"]
    with pytest.raises(
        ValueError,
        match=f"Superior Object class {superior_name} not found in schema.",
    ):
        await create_object_class(session=session, **object_class_data)


@pytest.mark.asyncio
async def test_modify_object_class(session: AsyncSession) -> None:
    """Test modify Object Class."""
    attribute_type_data: dict = {
        "oid": "1.2.3.4.5",
        "name": "customTestAttribute",
        "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        "single_value": True,
        "no_user_modification": False,
        "is_system": False,
    }
    await create_attribute_type(session=session, **attribute_type_data)

    object_class_data: dict = {
        "oid": "1.2.3.4.5",
        "name": "customTestClass",
        "superior_name": None,
        "kind": "STRUCTURAL",
        "is_system": True,
        "attribute_types_must": [],
        "attribute_types_may": [],
    }
    await create_object_class(session=session, **object_class_data)

    object_class = await get_object_class_by_name(
        object_class_data["name"],
        session=session,
    )
    assert object_class is not None

    new_statement = ObjectClassUpdateSchema(
        attribute_types_must=[],
        attribute_types_may=["customTestAttribute"],
    )
    await modify_object_class(
        session=session,
        object_class=object_class,
        new_statement=new_statement,
    )

    object_class = await get_object_class_by_name(
        object_class_data["name"],
        session=session,
    )
    assert object_class is not None
    assert object_class.is_structural is True
    assert set(object_class.attribute_types_must_display) == set(
        new_statement.attribute_types_must
    )
    assert set(object_class.attribute_types_may_display) == set(
        new_statement.attribute_types_may
    )


@pytest.mark.asyncio
async def test_delete_object_class(session: AsyncSession) -> None:
    """Create Object Class."""
    object_class_data: dict = {
        "oid": "1.2.3.4.5.6",
        "name": "customTestClass",
        "superior_name": None,
        "kind": "STRUCTURAL",
        "is_system": False,
        "attribute_types_must": [],
        "attribute_types_may": [],
    }
    object_class_name = object_class_data["name"]

    await create_object_class(session=session, **object_class_data)
    object_class = await get_object_class_by_name(
        object_class_name,
        session=session,
    )
    assert object_class is not None

    await delete_object_classes_by_names(
        session=session,
        object_classes_names=[object_class_name],
    )
    object_class = await get_object_class_by_name(
        object_class_name,
        session=session,
    )
    assert object_class is None
