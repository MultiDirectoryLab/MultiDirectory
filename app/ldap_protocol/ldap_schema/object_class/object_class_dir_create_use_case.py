"""Identity use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from constants import CONFIGURATION_DIR_NAME
from entities import Attribute, Directory
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.roles.role_use_case import RoleUseCase
from repo.pg.tables import queryable_attr as qa


class CreateDirectoryLikeAsObjectClassUseCase:
    """Setup use case."""

    __session: AsyncSession
    __entity_type_use_case: EntityTypeUseCase
    __role_use_case: RoleUseCase
    __parent: Directory | None

    def __init__(
        self,
        session: AsyncSession,
        entity_type_use_case: EntityTypeUseCase,
        role_use_case: RoleUseCase,
    ) -> None:
        """Initialize Setup use case.

        :param session: SQLAlchemy AsyncSession

        return: None.
        """
        self.__session = session
        self.__entity_type_use_case = entity_type_use_case
        self.__role_use_case = role_use_case
        self.__parent = None

    async def create_dir(
        self,
        data: dict,
        is_system: bool,
    ) -> None:
        """Create data recursively."""
        if not self.__parent:
            q = await self.__session.execute(
                select(Directory)
                .where(qa(Directory.name) == CONFIGURATION_DIR_NAME),
            )  # fmt: skip
            self.__parent = q.one()[0]

        dir_ = Directory(
            is_system=is_system,
            object_class=data["object_class"],
            name=data["name"],
        )
        dir_.groups = []
        dir_.create_path(self.__parent, dir_.get_dn_prefix())

        self.__session.add(dir_)
        await self.__session.flush()
        dir_.parent_id = self.__parent.id
        await self.__session.refresh(dir_, ["id"])

        self.__session.add(
            Attribute(
                name=dir_.rdname,
                value=dir_.name,
                directory_id=dir_.id,
            ),
        )

        if "attributes" in data:
            for name, values in data["attributes"].items():
                for value in values:
                    self.__session.add(
                        Attribute(
                            directory_id=dir_.id,
                            name=name,
                            value=value if isinstance(value, str) else None,
                            bvalue=value if isinstance(value, bytes) else None,
                        ),
                    )

            self.__session.add(
                Attribute(
                    directory_id=dir_.id,
                    name="objectClass",
                    value=dir_.object_class if isinstance(value, str) else None,  # noqa: E501
                    bvalue=None,
                ),
            )  # fmt: skip

        await self.__session.flush()

        await self.__session.refresh(
            instance=dir_,
            attribute_names=["attributes"],
        )

        entity_type = await self.__entity_type_use_case.get_one_raw_by_name(
            EntityTypeNames.OBJECT_CLASS,
        )
        await self.__entity_type_use_case.attach_entity_type_to_directory(
            directory=dir_,
            is_system_entity_type=True,
            entity_type=entity_type,
        )
        await self.__session.flush()

        await self.__role_use_case.inherit_parent_aces(
            parent_directory=self.__parent,
            directory=dir_,
        )
        await self.__session.flush()
