"""Directory DAO.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from constants import CONFIGURATION_DIR_NAME
from entities import Directory, EntityType
from repo.pg.tables import queryable_attr as qa


class DirectoryDAO:
    """Directory DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Directory DAO with session."""
        self.__session = session

    async def delete_configuration_dir(self) -> None:
        """Delete a Directory by ID."""
        await self.__session.execute(
            delete(Directory)
            .where(qa(Directory.name) == CONFIGURATION_DIR_NAME),
        )  # fmt: skip
        await self.__session.flush()

    async def create_directory(
        self,
        name: str,
        is_system: bool,
        parent_dir: Directory,
    ) -> Directory:
        """Create a Directory and return it with id populated."""
        directory = Directory(
            is_system=is_system,
            object_class="",
            name=name,
        )
        directory.groups = []
        directory.create_path(parent_dir, directory.get_dn_prefix())
        self.__session.add(directory)
        await self.__session.flush()

        directory.parent_id = parent_dir.id
        await self.__session.refresh(directory, ["id"])
        return directory

    async def get_all_without_entity_type(self) -> list[Directory]:
        """Get all Directories without Entity Type."""
        result = await self.__session.scalars(
            select(Directory)
            .where(qa(Directory.entity_type_id).is_(None))
            .options(
                selectinload(qa(Directory.attributes)),
                selectinload(qa(Directory.entity_type)),
            ),
        )
        return list(result.all())

    async def get_configuration_dir(self) -> Directory:
        """Get configuration directory."""
        result = await self.__session.execute(
            select(Directory)
            .where(qa(Directory.name) == CONFIGURATION_DIR_NAME),
        )  # fmt: skip
        return result.scalar_one()

    async def get_all_dir_ids_by_entity_type_name(
        self,
        name: str,
    ) -> list[int]:
        """Get all Directory IDs by Entity Type name."""
        result = await self.__session.scalars(
            select(qa(Directory.id))
            .join(qa(Directory.entity_type))
            .where(qa(EntityType.name) == name),
        )
        return list(result.all())

    async def bind_entity_type(
        self,
        directory: Directory,
        entity_type_id: int | None,
    ) -> None:
        """Ensure the Directory.entity_type relationship is loaded."""
        directory.entity_type_id = entity_type_id
        await self.__session.flush()
        await self.__session.refresh(
            directory,
            attribute_names=["entity_type"],
        )
