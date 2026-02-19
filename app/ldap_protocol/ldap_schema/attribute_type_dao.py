"""Attribute Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Sequence

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from abstract_dao import AbstractDAO
from entities import AttributeType, Directory, EntityType
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeNotFoundError,
)
from ldap_protocol.ldap_schema.setup_gateway import CreateAttributeDirGateway
from ldap_protocol.utils.pagination import (
    PaginationParams,
    PaginationResult,
    build_paginated_search_query,
)
from repo.pg.tables import queryable_attr as qa

_convert_model_to_dto = get_converter(
    AttributeType,
    AttributeTypeDTO,
    recipe=[
        allow_unlinked_optional(P[AttributeTypeDTO].object_class_names),
    ],
)
_convert_dto_to_model = get_converter(
    AttributeTypeDTO,
    AttributeType,
    recipe=[
        link_function(
            lambda _: None,
            P[AttributeType].id,
        ),
    ],
)


class AttributeTypeDAO(AbstractDAO[AttributeTypeDTO, str]):
    """Attribute Type DAO."""

    __session: AsyncSession
    __create_attribute_dir_gateway: CreateAttributeDirGateway

    def __init__(
        self,
        session: AsyncSession,
        create_attribute_dir_gateway: CreateAttributeDirGateway,
    ) -> None:
        """Initialize Attribute Type DAO with session."""
        self.__session = session
        self.__create_attribute_dir_gateway = create_attribute_dir_gateway

    async def get_depricated(
        self,
        name: str,
    ) -> AttributeTypeDTO:  # TODO что с этим делать то епта
        return _convert_model_to_dto(await self._get_one_raw_by_name(name))

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

    async def get_all(self) -> list[AttributeTypeDTO]:
        """Get all Attribute Types."""
        return [
            _convert_model_to_dto(attribute_type)
            for attribute_type in await self.__session.scalars(
                select(AttributeType),
            )
        ]

    async def create_deprecated(self, dto: AttributeTypeDTO) -> None:
        """Create Attribute Type."""
        try:
            attribute_type = _convert_dto_to_model(dto)
            self.__session.add(attribute_type)
            await self.__session.flush()

        except IntegrityError:
            raise AttributeTypeAlreadyExistsError(
                f"Attribute Type with oid '{dto.oid}' and name"
                + f" '{dto.name}' already exists.",
            )

    async def create(self, dto: AttributeTypeDTO[None]) -> None:
        """Create Attribute Type."""
        try:
            await self.__create_attribute_dir_gateway.create_dir(
                data={
                    "name": dto.name,
                    "object_class": "attributeSchema",
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

    # TODO сделай обновление пачки update bulk 100 times

    async def update_depricated(
        self,
        name: str,
        dto: AttributeTypeDTO,
    ) -> None:
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
        obj = await self._get_one_raw_by_name(name)

        obj.is_included_anr = dto.is_included_anr

        if not obj.is_system:
            obj.syntax = dto.syntax
            obj.single_value = dto.single_value
            obj.no_user_modification = dto.no_user_modification

        await self.__session.flush()

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

    async def update_sys_flags_depricated(
        self,
        name: str,
        dto: AttributeTypeDTO,
    ) -> None:
        """Update system flags of Attribute Type."""
        obj = await self._get_one_raw_by_name(name)
        obj.system_flags = dto.system_flags
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
        """Delete Attribute Type."""
        attribute_type = await self._get_one_raw_by_name(name)
        await self.__session.delete(attribute_type)
        await self.__session.flush()

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult[AttributeType, AttributeTypeDTO]:
        """Retrieve paginated Attribute Types.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of Attribute Types and metadata.
        """
        query = build_paginated_search_query(
            model=AttributeType,
            order_by_field=qa(AttributeType.id),
            params=params,
            search_field=qa(AttributeType.name),
        )

        return await PaginationResult[AttributeType, AttributeTypeDTO].get(
            params=params,
            query=query,
            converter=_convert_model_to_dto,
            session=self.__session,
        )

    async def _get_one_raw_by_name(self, name: str) -> AttributeType:
        attribute_type = await self.__session.scalar(
            select(AttributeType)
            .filter_by(name=name),
        )  # fmt: skip

        if not attribute_type:
            raise AttributeTypeNotFoundError(
                f"Attribute Type with name '{name}' not found.",
            )
        return attribute_type

    async def get_all_raw_by_names_deprecated(
        self,
        names: list[str] | set[str],
    ) -> Sequence[AttributeType]:
        """Get list of Attribute Types by names."""
        res = await self.__session.scalars(
            select(AttributeType)
            .where(qa(AttributeType.name).in_(names)),
        )  # fmt: skip
        return res.all()

    async def get_all_by_names(
        self,
        names: list[str] | set[str],
    ) -> list[AttributeTypeDTO[int]]:
        """Get list of Attribute Types by names.

        :param list[str] names: Attribute Type names.
        :return list[AttributeTypeDTO]: List of Attribute Types.
        """
        if not names:
            return []

        query = await self.__session.scalars(
            select(AttributeType)
            .where(qa(AttributeType.name).in_(names)),
        )  # fmt: skip
        return list(map(_convert_model_to_dto, query.all()))

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Attribute Types by names.

        :param list[str] names: List of Attribute Types names.
        :return None: None.
        """
        if not names:
            return

        await self.__session.execute(
            delete(AttributeType)
            .where(
                qa(AttributeType.name).in_(names),
                qa(AttributeType.is_system).is_(False),
            ),
        )  # fmt: skip
        await self.__session.flush()
