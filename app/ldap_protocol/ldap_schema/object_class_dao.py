"""Object Class DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    BaseSchemaModel,
    PaginationParams,
    PaginationResult,
)
from models import EntityType, KindType, ObjectClass

OBJECT_CLASS_KINDS_ALLOWED: tuple[KindType, ...] = (
    "STRUCTURAL",
    "ABSTRACT",
    "AUXILIARY",
)


class ObjectClassSchema(BaseSchemaModel):
    """Object Class Schema."""

    oid: str
    name: str
    superior_name: str | None
    kind: KindType
    is_system: bool
    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]

    @classmethod
    def from_db(cls, object_class: ObjectClass) -> "ObjectClassSchema":
        """Create an instance of Object Class Schema from database."""
        return cls(
            oid=object_class.oid,
            name=object_class.name,
            superior_name=object_class.superior_name,
            kind=object_class.kind,
            is_system=object_class.is_system,
            attribute_type_names_must=object_class.attribute_type_names_must,
            attribute_type_names_may=object_class.attribute_type_names_may,
        )


class ObjectClassPaginationSchema(BasePaginationSchema[ObjectClassSchema]):
    """Object Class Schema with pagination result."""

    items: list[ObjectClassSchema]


class ObjectClassUpdateSchema(BaseModel):
    """Object Class Schema for modify/update."""

    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]


class ObjectClassDAO:
    """Object Class DAO."""

    _session: AsyncSession
    _attribute_type_dao: AttributeTypeDAO

    def __init__(
        self,
        session: AsyncSession,
        attribute_type_dao: AttributeTypeDAO,
    ) -> None:
        """Initialize Object Class DAO with session."""
        self._session = session
        self._attribute_type_dao = attribute_type_dao

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Object Classes.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of Object Classes and metadata.
        """
        return await PaginationResult[ObjectClass].get(
            params=params,
            query=select(ObjectClass).order_by(ObjectClass.id),
            sqla_model=ObjectClass,
            session=self._session,
        )

    async def create_one(
        self,
        oid: str,
        name: str,
        superior_name: str | None,
        kind: KindType,
        is_system: bool,
        attribute_type_names_must: list[str],
        attribute_type_names_may: list[str],
    ) -> None:
        """Create a new Object Class.

        :param str oid: OID.
        :param str name: Name.
        :param str | None superior_name: Parent Object Class.
        :param KindType kind: Kind.
        :param bool is_system: Object Class is system.
        :param list[str] attribute_type_names_must: Attribute Types must.
        :param list[str] attribute_type_names_may: Attribute Types may.
        :return None.
        """
        if kind not in OBJECT_CLASS_KINDS_ALLOWED:
            raise ValueError(f"Object class kind is not valid: {kind}.")

        superior = (
            await self.get_one_by_name(superior_name)
            if superior_name
            else None
        )
        if superior_name and not superior:
            raise ValueError(
                f"Superior Object class {superior_name} not found in schema."
            )

        attribute_types_may_filtered = [
            name
            for name in attribute_type_names_may
            if name not in attribute_type_names_must
        ]

        attribute_types_must = await self._attribute_type_dao.get_all_by_names(
            attribute_type_names_must
        )
        attribute_types_may = await self._attribute_type_dao.get_all_by_names(
            attribute_types_may_filtered
        )

        object_class = ObjectClass(
            oid=oid,
            name=name,
            superior=superior,
            kind=kind,
            is_system=is_system,
            attribute_types_must=attribute_types_must,
            attribute_types_may=attribute_types_may,
        )
        self._session.add(object_class)

    async def count_exists_object_class_by_names(
        self,
        object_class_names: list[str],
    ) -> int:
        """Count exists Object Class by names.

        :param list[str] object_class_names: Object Class names.
        :return int.
        """
        count_query = (
            select(func.count())
            .select_from(ObjectClass)
            .where(ObjectClass.name.in_(object_class_names))
        )
        result = await self._session.scalars(count_query)
        return result.one()

    async def is_all_object_classes_exists(
        self,
        object_class_names: list[str],
    ) -> bool:
        """Check if all Object Classes exist.

        :param list[str] object_class_names: Object Class names.
        :return bool.
        """
        count_ = await self.count_exists_object_class_by_names(
            object_class_names
        )

        return bool(count_ == len(object_class_names))

    async def get_one_by_name(
        self,
        object_class_name: str,
    ) -> ObjectClass | None:
        """Get single Object Class by name.

        :param str object_class_name: Object Class name.
        :return ObjectClass | None: Instance of Object Class or None.
        """
        return await self._session.scalar(
            select(ObjectClass)
            .where(ObjectClass.name == object_class_name)
        )  # fmt: skip

    async def get_all_by_names(
        self,
        object_class_names: list[str] | set[str],
    ) -> list[ObjectClass]:
        """Get list of Object Classes by names.

        :param list[str] object_class_names: Object Classes names.
        :return list[ObjectClass]: List of Object Classes.
        """
        query = await self._session.scalars(
            select(ObjectClass)
            .where(ObjectClass.name.in_(object_class_names))
            .options(
                selectinload(ObjectClass.attribute_types_must),
                selectinload(ObjectClass.attribute_types_may),
            )
        )  # fmt: skip
        return list(query.all())

    async def modify_one(
        self,
        object_class: ObjectClass,
        new_statement: ObjectClassUpdateSchema,
    ) -> None:
        """Modify Object Class.

        :param ObjectClass object_class: Object Class.
        :param ObjectClassUpdateSchema new_statement: New statement ObjectClass
        :return None.
        """
        object_class.attribute_types_must.clear()
        object_class.attribute_types_must.extend(
            await self._attribute_type_dao.get_all_by_names(
                new_statement.attribute_type_names_must
            ),
        )

        attribute_types_may_filtered = [
            name
            for name in new_statement.attribute_type_names_may
            if name not in new_statement.attribute_type_names_must
        ]
        object_class.attribute_types_may.clear()
        object_class.attribute_types_may.extend(
            await self._attribute_type_dao.get_all_by_names(
                attribute_types_may_filtered
            ),
        )

    async def delete_all_by_names(
        self,
        object_classes_names: list[str],
    ) -> None:
        """Delete not system Object Classes by Names.

        :param list[str] object_classes_names: Object Classes names.
        :return None.
        """
        await self._session.execute(
            delete(ObjectClass)
            .where(
                ObjectClass.name.in_(object_classes_names),
                ObjectClass.is_system.is_(False),
                ~ObjectClass.name.in_(
                    select(func.unnest(EntityType.object_class_names))
                    .where(EntityType.object_class_names.isnot(None))
                ),
            ),
        )  # fmt: skip
