"""Attribute Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.exceptions import (
    InstanceCantModifyError,
    InstanceNotFoundError,
)
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    BaseSchemaModel,
    PaginationParams,
    PaginationResult,
)
from models import AttributeType


class AttributeTypeSchema(BaseSchemaModel):
    """Attribute Type Schema."""

    oid: str
    name: str
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool

    @classmethod
    def from_db(cls, attribute_type: AttributeType) -> "AttributeTypeSchema":
        """Create an instance from database.

        Args:
            attribute_type (AttributeType): instance of AttributeType

        Returns:
            AttributeTypeSchema: serialized AttributeType.
        """
        return cls(
            oid=attribute_type.oid,
            name=attribute_type.name,
            syntax=attribute_type.syntax,
            single_value=attribute_type.single_value,
            no_user_modification=attribute_type.no_user_modification,
            is_system=attribute_type.is_system,
        )


class AttributeTypeUpdateSchema(BaseModel):
    """Attribute Type Schema for modify/update."""

    syntax: str
    single_value: bool
    no_user_modification: bool


class AttributeTypePaginationSchema(BasePaginationSchema[AttributeTypeSchema]):
    """Attribute Type Schema with pagination result."""

    items: list[AttributeTypeSchema]


class AttributeTypeDAO:
    """Attribute Type DAO."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Attribute Type DAO with session."""
        self._session = session

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated attribute_types.

        Args:
            params (PaginationParams): page_size and page_number.

        Returns:
            PaginationResult: Chunk of attribute_types and metadata.
        """
        return await PaginationResult[AttributeType].get(
            params=params,
            query=select(AttributeType).order_by(AttributeType.id),
            sqla_model=AttributeType,
            session=self._session,
        )

    async def create_one(
        self,
        oid: str,
        name: str,
        syntax: str,
        single_value: bool,
        no_user_modification: bool,
        is_system: bool,
    ) -> None:
        """Create a new Attribute Type.

        Args:
            oid (str): OID.
            name (str): Name.
            syntax (str): Syntax.
            single_value (bool): Single value.
            no_user_modification (bool): User can't modify it.
            is_system (bool): Attribute Type is system.
        """
        attribute_type = AttributeType(
            oid=oid,
            name=name,
            syntax=syntax,
            single_value=single_value,
            no_user_modification=no_user_modification,
            is_system=is_system,
        )
        self._session.add(attribute_type)

    async def get_one_by_name(
        self,
        attribute_type_name: str,
    ) -> AttributeType:
        """Get single Attribute Type by name.

        Args:
            attribute_type_name (str): Attribute Type name.

        Returns:
            AttributeType | None: Attribute Type.

        Raises:
            InstanceNotFoundError: Attribute Type not found.
        """
        attribute_type = await self._session.scalar(
            select(AttributeType)
            .where(AttributeType.name == attribute_type_name)
        )  # fmt: skip

        if not attribute_type:
            raise InstanceNotFoundError(
                f"Attribute Type with name '{attribute_type_name}' not found."
            )

        return attribute_type

    async def get_all_by_names(
        self,
        attribute_type_names: list[str] | set[str],
    ) -> list[AttributeType]:
        """Get list of Attribute Types by names.

        Args:
            attribute_type_names (list[str]): Attribute Type names.

        Returns:
            list[AttributeType]: List of Attribute Types.
        """
        if not attribute_type_names:
            return []

        query = await self._session.scalars(
            select(AttributeType)
            .where(AttributeType.name.in_(attribute_type_names)),
        )  # fmt: skip
        return list(query.all())

    async def modify_one(
        self,
        attribute_type: AttributeType,
        new_statement: AttributeTypeUpdateSchema,
    ) -> None:
        """Modify Attribute Type.

        Args:
            attribute_type (AttributeType): Attribute Type.
            new_statement (AttributeTypeUpdateSchema): Attribute Type
                Schema.

        Raises:
            InstanceCantModifyError: System Attribute Type cannot be modified.
        """
        if attribute_type.is_system:
            raise InstanceCantModifyError(
                "System Attribute Type cannot be modified."
            )

        attribute_type.syntax = new_statement.syntax
        attribute_type.single_value = new_statement.single_value
        attribute_type.no_user_modification = (
            new_statement.no_user_modification
        )

    async def delete_all_by_names(
        self,
        attribute_type_names: list[str],
    ) -> None:
        """Delete not system Attribute Types by names.

        Args:
            attribute_type_names (list[str]): List of Attribute Types OIDs.
        """
        if not attribute_type_names:
            return None

        await self._session.execute(
            delete(AttributeType)
            .where(
                AttributeType.name.in_(attribute_type_names),
                AttributeType.is_system.is_(False),
            ),
        )  # fmt: skip
