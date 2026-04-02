"""Attribute DAO.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from entities import Attribute
from ldap_protocol.ldap_schema.dto import AttributeDTO


class AttributeDAO:
    """Attribute DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Attribute DAO with session."""
        self.__session = session

    async def add_directory_name_attribute(
        self,
        directory_id: int,
        attribute_dto: AttributeDTO,
    ) -> None:
        """Add the RDN attribute for a Directory."""
        self.__session.add(
            Attribute(
                name=attribute_dto.name,
                value=attribute_dto.values[0] if attribute_dto.values else "",
                directory_id=directory_id,
            ),
        )

    async def add_attributes_from_dto(
        self,
        directory_id: int,
        attributes: tuple[AttributeDTO, ...],
    ) -> None:
        """Add Attributes from a CreateDirDTO payload."""
        for attribute_dto in attributes:
            for value in attribute_dto.values:
                if not isinstance(value, str):
                    raise ValueError("Only string values are supported.")

                self.__session.add(
                    Attribute(
                        directory_id=directory_id,
                        name=attribute_dto.name,
                        value=value,
                        bvalue=None,
                    ),
                )
