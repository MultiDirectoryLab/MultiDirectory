"""Attribute Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from abstract_dao import AbstractDAO
from entities import Directory, EntityType
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.attribute_type_dir_gateway import (
    CreateDirectoryLikeAsAttributeTypeGateway,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeNotFoundError,
)
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult
from repo.pg.tables import queryable_attr as qa


def _convert_model_to_dto(directory: Directory) -> AttributeTypeDTO:
    return AttributeTypeDTO[int](
        id=directory.id,
        name=directory.name,
        oid=directory.attributes_dict["oid"][0],
        syntax=directory.attributes_dict["syntax"][0],
        single_value=directory.attributes_dict["single_value"][0] == "True",
        no_user_modification=directory.attributes_dict["no_user_modification"][
            0
        ]
        == "True",
        is_system=directory.attributes_dict["is_system"][0] == "True",
        system_flags=int(directory.attributes_dict["system_flags"][0]),
        is_included_anr=directory.attributes_dict["is_included_anr"][0]
        == "True",
        object_class_names=set(),
    )


class AttributeTypeDAO(AbstractDAO[AttributeTypeDTO, str]):
    """Attribute Type DAO."""

    __session: AsyncSession
    __create_attribute_dir_gateway: CreateDirectoryLikeAsAttributeTypeGateway

    def __init__(
        self,
        session: AsyncSession,
        create_attribute_dir_gateway: CreateDirectoryLikeAsAttributeTypeGateway,
    ) -> None:
        """Initialize Attribute Type DAO with session."""
        self.__session = session
        self.__create_attribute_dir_gateway = create_attribute_dir_gateway

    async def get_dir(self, name: str) -> Directory | None:
        res = await self.__session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .filter(
                qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE,
                qa(Directory.name) == name,
            )
            .options(selectinload(qa(Directory.attributes))),
        )
        dir_ = res.first()
        return dir_

    async def get(self, name: str) -> AttributeTypeDTO:
        """Get Attribute Type by name."""
        dir_ = await self.get_dir(name)
        if not dir_:
            raise AttributeTypeNotFoundError(
                f"Attribute Type with name '{name}' not found.",
            )
        dto = AttributeTypeDTO[int](
            id=dir_.id,
            name=dir_.name,
            oid=dir_.attributes_dict["oid"][0],
            syntax=dir_.attributes_dict["syntax"][0],
            single_value=dir_.attributes_dict["single_value"][0] == "True",
            no_user_modification=dir_.attributes_dict["no_user_modification"][
                0
            ]
            == "True",
            is_system=dir_.attributes_dict["is_system"][0] == "True",
            system_flags=int(dir_.attributes_dict["system_flags"][0]),
            is_included_anr=dir_.attributes_dict["is_included_anr"][0]
            == "True",
        )
        return dto

    async def create(self, dto: AttributeTypeDTO[None]) -> None:
        """Create Attribute Type."""
        try:
            await self.__create_attribute_dir_gateway.create_dir(
                data={
                    "name": dto.name,
                    "object_class": "",
                    "attributes": {
                        "objectClass": ["top", "attributeSchema"],
                        "oid": [str(dto.oid)],
                        "name": [str(dto.name)],
                        "syntax": [str(dto.syntax)],
                        "single_value": [str(dto.single_value)],
                        "no_user_modification": [
                            str(dto.no_user_modification),
                        ],
                        "is_system": [str(dto.is_system)],  # TODO asd223edfsda
                        "system_flags": [str(dto.system_flags)],
                        "is_included_anr": [str(dto.is_included_anr)],
                    },
                    "children": [],
                },
                is_system=dto.is_system,  # TODO asd223edfsda связать два поля
            )
            await self.__session.flush()

        except IntegrityError:
            raise AttributeTypeAlreadyExistsError(
                f"Attribute Type with oid '{dto.oid}' and name"
                + f" '{dto.name}' already exists.",
            )

    # TODO сделай обновление пачки update bulk 100 times. а зачем? я забыл

    async def update(self, name: str, dto: AttributeTypeDTO) -> None:
        """Update Attribute Type.

        Docs:
            ANR (Ambiguous Name Resolution) inclusion can be modified for
            all attributes, including system ones, as it's a search
            optimization setting that doesn't affect the LDAP schema
            structure or data integrity.

            Other properties (`syntax`, `single_value`, `no_user_modification`)
            can only be modified for non-system attributes to preserve
            LDAP schema integrity.
        """
        obj = await self.get_dir(name)

        if not obj:
            raise AttributeTypeNotFoundError(
                f"Attribute Type with name '{name}' not found.",
            )

        for attr in obj.attributes:
            if not obj.is_system:
                if attr.name == "syntax":
                    attr.value = dto.syntax
                elif attr.name == "single_value":
                    attr.value = str(dto.single_value)
                elif attr.name == "no_user_modification":
                    attr.value = str(dto.no_user_modification)
            else:
                if attr.name == "is_included_anr":
                    attr.value = str(dto.is_included_anr)

        await self.__session.flush()

    async def update_sys_flags(
        self,
        name: str,
        dto: AttributeTypeDTO,
    ) -> None:
        """Update system flags of Attribute Type."""
        obj = await self.get_dir(name)
        if not obj:
            raise AttributeTypeNotFoundError(
                f"Attribute Type with name '{name}' not found.",
            )

        for attr in obj.attributes:
            if attr.name == "system_flags":
                attr.value = str(dto.system_flags)

        await self.__session.flush()

    async def delete(self, name: str) -> None:
        return None

    async def get_all(self) -> list[AttributeTypeDTO]:
        return []

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult[Directory, AttributeTypeDTO]:
        """Retrieve paginated Attribute Types.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of Attribute Types and metadata.
        """
        filters = [
            qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE,
        ]
        if params.query:
            filters.append(
                qa(Directory.name).like(f"%{params.query}%"),
            )

        query = (
            select(Directory)
            .join(qa(Directory.entity_type))
            .filter(*filters)
            .options(selectinload(qa(Directory.attributes)))
            .order_by(qa(Directory.id))
        )

        return await PaginationResult[Directory, AttributeTypeDTO].get(
            params=params,
            query=query,
            converter=_convert_model_to_dto,
            session=self.__session,
        )

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Attribute Types by names.

        :param list[str] names: List of Attribute Types names.
        :return None: None.
        """
        if not names:
            return

        await self.__session.execute(
            delete(Directory).where(
                qa(Directory.entity_type)
                .has(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE),
                qa(Directory.name).in_(names),
                qa(Directory.is_system).is_(False),
            ),
        )  # fmt: skip
        await self.__session.flush()
