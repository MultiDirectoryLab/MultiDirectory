"""Identity use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from itertools import chain

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from constants import CONFIGURATION_DIR_NAME
from entities import Attribute, Directory, Group
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.attribute_value_validator import (
    AttributeValueValidator,
)
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.roles.role_use_case import RoleUseCase
from repo.pg.tables import queryable_attr as qa


class CreateDirectoryLikeAsAttributeTypeUseCase:
    """Setup use case."""

    __session: AsyncSession
    __entity_type_use_case: EntityTypeUseCase
    __attribute_value_validator: AttributeValueValidator
    __role_use_case: RoleUseCase
    __parent: Directory | None

    def __init__(
        self,
        session: AsyncSession,
        entity_type_use_case: EntityTypeUseCase,
        attribute_value_validator: AttributeValueValidator,
        role_use_case: RoleUseCase,
    ) -> None:
        """Initialize Setup use case.

        :param session: SQLAlchemy AsyncSession

        return: None.
        """
        self.__session = session
        self.__entity_type_use_case = entity_type_use_case
        self.__attribute_value_validator = attribute_value_validator
        self.__role_use_case = role_use_case
        self.__parent = None

    async def flush(self) -> None:
        await self.__session.flush()

    async def create_dir(
        self,
        data: dict,
        is_system: bool,
    ) -> None:
        """Create data recursively."""
        if not self.__parent:
            self.__parent = (
                await self.__session.execute(
                    select(Directory).where(
                        qa(Directory.name) == CONFIGURATION_DIR_NAME,
                    ),
                )
            ).one()[0]

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
            attrs = chain(
                data["attributes"].items(),
                [("objectClass", [dir_.object_class])],
            )  # TODO ну и урод этот однострчник, сделай потом проще

            for name, values in attrs:
                for value in values:
                    self.__session.add(
                        Attribute(
                            directory_id=dir_.id,
                            name=name,
                            value=value if isinstance(value, str) else None,
                            bvalue=value if isinstance(value, bytes) else None,
                        ),
                    )

        await self.__session.flush()

        await self.__session.refresh(
            instance=dir_,
            attribute_names=["attributes"],
        )
        # TODO FIXME
        entity_type = await self.__entity_type_use_case.get_one_raw_by_name(
            EntityTypeNames.ATTRIBUTE_TYPE,
        )
        await self.__entity_type_use_case.attach_entity_type_to_directory(
            directory=dir_,
            is_system_entity_type=True,
            entity_type=entity_type,
        )
        if not self.__attribute_value_validator.is_directory_valid(dir_):
            raise ValueError("Invalid directory attribute values")
        await self.__session.flush()

        await self.__role_use_case.inherit_parent_aces(
            parent_directory=self.__parent,
            directory=dir_,
        )

    async def _get_group(self, name: str) -> Group:
        """Get group by name.

        :param str name: group name
        :return Group: group
        """
        retval = await self.__session.scalars(
            select(Group)
            .join(qa(Group.directory))
            .filter(
                qa(Directory.name) == name,
                qa(Directory.object_class) == "group",
            ),
        )
        return retval.one()
