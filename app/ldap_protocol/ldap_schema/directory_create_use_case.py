"""Identity use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.attribute_dao import AttributeDAO
from ldap_protocol.ldap_schema.directory_dao import DirectoryDAO
from ldap_protocol.ldap_schema.dto import AttributeDTO, DirCreateDTO
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.ldap_schema.exceptions import CantCreateDirectoryError
from ldap_protocol.roles.role_use_case import RoleUseCase

if TYPE_CHECKING:
    from entities import Directory


def _get_object_sid(base_dn_sid: str, rid: int) -> str:
    return f"{base_dn_sid}-{rid}"


def _is_dn_in_base_directory(path_dn: str, entry: str) -> bool:
    """Check if an entry in a base dn."""
    return entry.lower().endswith(path_dn.lower())


class DirectoryCreateUseCase:
    """Setup use case."""

    __session: AsyncSession
    __entity_type_use_case: EntityTypeUseCase
    __role_use_case: RoleUseCase
    __directory_dao: DirectoryDAO
    __attribute_dao: AttributeDAO

    def __init__(
        self,
        session: AsyncSession,
        entity_type_use_case: EntityTypeUseCase,
        role_use_case: RoleUseCase,
        directory_dao: DirectoryDAO,
        attribute_dao: AttributeDAO,
    ) -> None:
        """Initialize."""
        self.__session = session
        self.__entity_type_use_case = entity_type_use_case
        self.__role_use_case = role_use_case
        self.__directory_dao = directory_dao
        self.__attribute_dao = attribute_dao

    async def get_configuration_dir(self) -> "Directory":
        """Get configuration directory."""
        return await self.__directory_dao.get_configuration_dir()

    async def delete_configuration_dir(self) -> None:
        """Delete configuration directory."""
        await self.__directory_dao.delete_configuration_dir()

    async def create_dir(
        self,
        dto: DirCreateDTO,
        parent_dir: "Directory",
    ) -> None:
        """Create."""
        base_directory_paths_and_sids = (
            await self.__directory_dao.get_base_directory_paths_with_sid()
        )

        dir_ = await self.__directory_dao.create_directory(
            name=dto.name,
            is_system=dto.is_system,
            parent_dir=parent_dir,
        )

        for _path, _sid in base_directory_paths_and_sids:
            if _is_dn_in_base_directory(_path, dir_.path_dn):
                base_dn_sid = _sid
                break
        else:
            raise CantCreateDirectoryError("Cannot create a directory.")

        dir_.object_sid = _get_object_sid(base_dn_sid, dir_.id)

        attr_dto = AttributeDTO(name=dir_.rdname, values=[dir_.name])
        await self.__attribute_dao.add_directory_name_attribute(
            dir_.id,
            attr_dto,
        )

        await self.__attribute_dao.add_attributes_from_dto(
            directory_id=dir_.id,
            attributes=dto.attributes,
        )

        await self.__session.flush()

        await self.__session.refresh(
            instance=dir_,
            attribute_names=["attributes"],
        )

        entity_type = await self.__entity_type_use_case.get(
            dto.entity_type_name,
        )
        await self.__directory_dao.bind_entity_type(
            dir_,
            entity_type.id if entity_type else None,
        )
        await self.__session.flush()

        await self.__role_use_case.inherit_parent_aces(
            parent_directory=parent_dir,
            directory=dir_,
        )
        await self.__session.flush()
