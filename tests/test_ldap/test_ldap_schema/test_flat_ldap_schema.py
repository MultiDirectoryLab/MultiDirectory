"""Test flat LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_responses import PartialAttribute
from ldap_protocol.ldap_schema.attribute_type_crud import create_attribute_type
from ldap_protocol.ldap_schema.flat_ldap_schema import (
    _get_flat_attribute_type_names_by_object_class_names,
    get_flat_ldap_schema,
    validate_attributes_by_ldap_schema,
    validate_chunck_object_classes_by_ldap_schema,
)
from ldap_protocol.ldap_schema.object_class_crud import create_object_class
from models import ObjectClass
from tests.test_ldap.test_ldap_schema.test_flat_ldap_schema_datasets import (
    test_get_attribute_type_names_by_object_class_names_dataset,
    test_validate_attributes_by_ldap_schema_dataset,
    test_validate_attributes_by_ldap_schema_error_dataset,
    test_validate_chunck_object_classes_by_ldap_schema_dataset,
    test_validate_chunck_object_classes_by_ldap_schema_error_dataset,
)


@pytest.mark.asyncio
async def test_get_flat_ldap_schema(session: AsyncSession) -> None:
    """Get flat schema."""
    result = await session.scalars(select(ObjectClass))
    all_object_classes = list(result.all())
    flat_ldap_schema = await get_flat_ldap_schema(session)
    assert len(all_object_classes) == len(flat_ldap_schema)


@pytest.mark.parametrize(
    "dataset",
    test_get_attribute_type_names_by_object_class_names_dataset,
)
@pytest.mark.asyncio
async def test_get_attribute_type_names_by_object_class_names(
    dataset: dict,
    session: AsyncSession,
) -> None:
    """Test merge attribute type names."""
    for attribute_type in dataset["attribute_types"]:
        await create_attribute_type(**attribute_type, session=session)

    for object_class in dataset["object_classes"]:
        await create_object_class(**object_class, session=session)

    flat_ldap_schema = await get_flat_ldap_schema(session)
    must, may = await _get_flat_attribute_type_names_by_object_class_names(
        dataset["object_class_names"],
        flat_ldap_schema,
    )

    assert must == {i.lower() for i in dataset["result"]["must"]}
    assert may == {i.lower() for i in dataset["result"]["may"]}


@pytest.mark.asyncio
async def test_get_attribute_type_names_by_object_class_names_valerror(
    session: AsyncSession,
) -> None:
    """Test raises ValueError for not exists ObjectClass."""
    flat_ldap_schema = await get_flat_ldap_schema(session)
    with pytest.raises(ValueError):  # noqa: PT011
        await _get_flat_attribute_type_names_by_object_class_names(
            ["DoesNotExistObjectClassName"],
            flat_ldap_schema,
        )


@pytest.mark.parametrize(
    "dataset",
    test_validate_chunck_object_classes_by_ldap_schema_dataset,
)
@pytest.mark.asyncio
async def test_validate_chunck_object_classes_by_ldap_schema(
    dataset: dict,
    session: AsyncSession,
) -> None:
    """Test merge attribute type names."""
    for object_class in dataset["object_classes"]:
        await create_object_class(**object_class, session=session)

    flat_ldap_schema = await get_flat_ldap_schema(session)
    result = await validate_chunck_object_classes_by_ldap_schema(
        dataset["object_class_names"],
        flat_ldap_schema,
    )

    assert not result.alerts


@pytest.mark.parametrize(
    "dataset",
    test_validate_chunck_object_classes_by_ldap_schema_error_dataset,
)
@pytest.mark.asyncio
async def test_validate_chunck_object_classes_by_ldap_schema_error(
    dataset: dict,
    session: AsyncSession,
) -> None:
    """Test OBJECT_CLASS_VIOLATION errors if not contains STRUCTURAL."""
    for object_class in dataset["object_classes"]:
        await create_object_class(**object_class, session=session)

    flat_ldap_schema = await get_flat_ldap_schema(session)
    result = await validate_chunck_object_classes_by_ldap_schema(
        dataset["object_class_names"],
        flat_ldap_schema,
    )

    assert dataset["error"] in result.alerts


@pytest.mark.parametrize(
    "dataset",
    test_validate_attributes_by_ldap_schema_dataset,
)
@pytest.mark.asyncio
async def test_validate_attributes_by_ldap_schema(
    dataset: dict,
    session: AsyncSession,
) -> None:
    """Test merge attribute type names."""
    for attribute_type in dataset["attribute_types"]:
        await create_attribute_type(**attribute_type, session=session)

    for object_class in dataset["object_classes"]:
        await create_object_class(**object_class, session=session)

    attributes = [
        PartialAttribute(type=name, vals=values)
        for name, values in dataset["attributes"]
    ]
    flat_ldap_schema = await get_flat_ldap_schema(session)
    result = await validate_attributes_by_ldap_schema(
        attributes,
        dataset["object_class_names"],
        flat_ldap_schema,
    )

    assert not result.alerts
    for correct_attribute in result.attributes_accepted:
        assert correct_attribute.name in dataset["correct_attributes"]
        assert correct_attribute.name not in dataset["useless_attributes"]


@pytest.mark.parametrize(
    "dataset",
    test_validate_attributes_by_ldap_schema_error_dataset,
)
@pytest.mark.asyncio
async def test_validate_attributes_by_ldap_schema_error(
    dataset: dict,
    session: AsyncSession,
) -> None:
    """Test errors merge attribute type names."""
    for attribute_type in dataset["attribute_types"]:
        await create_attribute_type(**attribute_type, session=session)

    for object_class in dataset["object_classes"]:
        await create_object_class(**object_class, session=session)

    attributes = [
        PartialAttribute(type=name, vals=values)
        for name, values in dataset["attributes"]
    ]
    flat_ldap_schema = await get_flat_ldap_schema(session)
    result = await validate_attributes_by_ldap_schema(
        attributes,
        dataset["object_class_names"],
        flat_ldap_schema,
    )

    assert len(result.alerts) == 1
    assert dataset["error"] in result.alerts
