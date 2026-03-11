"""Identity use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from constants import CONFIGURATION_DIR_NAME
from entities import Attribute, Directory
from ldap_protocol.ldap_schema.dto import CreateDirDTO
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.ldap_schema.exceptions import (
    CantCreateDirectoryWithSchemaLikeAsDirectoryError,
)
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.helpers import (
    create_object_sid,
    is_dn_in_base_directory,
)
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa


class SchemaLikeAsDirectoryCreateUseCase:
    """Setup use case."""

    __session: AsyncSession
    __entity_type_use_case: EntityTypeUseCase
    __role_use_case: RoleUseCase
    __parent: Directory | None
    __base_directories: list[Directory] | None = None

    def __init__(
        self,
        session: AsyncSession,
        entity_type_use_case: EntityTypeUseCase,
        role_use_case: RoleUseCase,
    ) -> None:
        """Initialize."""
        self.__session = session
        self.__entity_type_use_case = entity_type_use_case
        self.__role_use_case = role_use_case
        self.__parent = None
        self.__base_directories = None

    async def create_dir(self, dto: CreateDirDTO) -> None:
        """Create."""
        if not self.__parent:
            q = await self.__session.execute(
                select(Directory)
                .where(qa(Directory.name) == CONFIGURATION_DIR_NAME),
            )  # fmt: skip
            self.__parent = q.one()[0]

        self.__base_directories = await get_base_directories(self.__session)

        dir_ = Directory(
            is_system=dto.is_system,
            object_class="",
            name=dto.name,
        )
        dir_.groups = []
        dir_.create_path(self.__parent, dir_.get_dn_prefix())
        self.__session.add(dir_)
        await self.__session.flush()

        dir_.parent_id = self.__parent.id
        await self.__session.refresh(dir_, ["id"])

        for base_directory in self.__base_directories:
            if is_dn_in_base_directory(base_directory, dir_.path_dn):
                base_dn = base_directory
                break
        else:
            raise CantCreateDirectoryWithSchemaLikeAsDirectoryError(
                "Cannot create a directory with schema like as directory.",
            )

        dir_.object_sid = create_object_sid(base_dn, dir_.id)

        self.__session.add(
            Attribute(
                name=dir_.rdname,
                value=dir_.name,
                directory_id=dir_.id,
            ),
        )

        for attribute_dto in dto.attributes:
            for value in attribute_dto.values:
                if not isinstance(value, str):
                    raise ValueError("Only string values are supported.")

                self.__session.add(
                    Attribute(
                        directory_id=dir_.id,
                        name=attribute_dto.name,
                        value=value,
                        bvalue=None,
                    ),
                )

        await self.__session.flush()

        await self.__session.refresh(
            instance=dir_,
            attribute_names=["attributes"],
        )

        dir_.entity_type = (
            await self.__entity_type_use_case.get_one_raw_by_name(
                dto.entity_type_name,
            )
        )
        await self.__session.flush()

        await self.__role_use_case.inherit_parent_aces(
            parent_directory=self.__parent,
            directory=dir_,
        )
        await self.__session.flush()
