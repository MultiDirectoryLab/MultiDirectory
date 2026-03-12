"""Access control entry DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import get_converter, link_function
from entities_legacy import AttributeTypeLegacy
from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from abstract_dao import AbstractDAO
from entities import AccessControlEntry, Directory, EntityType
from enums import AceType, EntityTypeNames, RoleScope
from ldap_protocol.utils.helpers import get_depth_by_dn
from ldap_protocol.utils.queries import get_path_filter, get_search_path
from repo.pg.tables import queryable_attr as qa

from .dataclasses import AccessControlEntryDTO
from .exceptions import (
    AccessControlEntryAddError,
    AccessControlEntryNotFoundError,
    AccessControlEntryUpdateError,
    NoValidDistinguishedNameError,
)

_convert = get_converter(
    AccessControlEntry,
    AccessControlEntryDTO,
    recipe=[
        link_function(lambda x: x.path, P[AccessControlEntryDTO].base_dn),
        link_function(lambda x: x.role_id, P[AccessControlEntryDTO].role_id),
        link_function(
            lambda x: x.role.name,
            P[AccessControlEntryDTO].role_name,
        ),
        link_function(
            lambda x: x.attribute_type_id,
            P[AccessControlEntryDTO].attribute_type_id,
        ),
        link_function(
            lambda x: x.entity_type_id,
            P[AccessControlEntryDTO].entity_type_id,
        ),
    ],
)


class AccessControlEntryDAO(AbstractDAO[AccessControlEntryDTO, int]):
    """Access control entry DAO."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Access Control Entry DAO with a database session."""
        self._session = session

    async def _get_raw(self, _id: int) -> AccessControlEntry:
        """Get an access control entry by its ID.

        :param int _id: ID of the access control entry to retrieve.
        :return: AccessControlEntry object.
        """
        query = (
            select(AccessControlEntry)
            .options(
                joinedload(qa(AccessControlEntry.attribute_type)),
                joinedload(qa(AccessControlEntry.entity_type)),
                joinedload(qa(AccessControlEntry.role)),
                selectinload(qa(AccessControlEntry.directories)),
            )
            .filter_by(id=_id)
        )
        retval = await self._session.scalar(query)
        if not retval:
            raise AccessControlEntryNotFoundError(
                f"AccessControlEntry with ID {_id} does not exist.",
            )
        return retval

    async def get(self, _id: int) -> AccessControlEntryDTO:
        """Get an access control entry by its ID.

        :param int _id: ID of the role to retrieve.
        :return: AccessControlEntryDTO object.
        """
        return _convert(await self._get_raw(_id))

    async def get_all(self) -> list[AccessControlEntryDTO]:
        """Get all access control entries.

        :return: List of AccessControlEntryDTO objects.
        """
        access_control_entries = (
            await self._session.scalars(
                select(AccessControlEntry).options(
                    joinedload(qa(AccessControlEntry.attribute_type)),
                    joinedload(qa(AccessControlEntry.entity_type)),
                    joinedload(qa(AccessControlEntry.role)),
                ),
            )
        ).all()
        return list(map(_convert, access_control_entries))

    async def _get_directories_with_scope(
        self,
        base_dn: str,
        scope: RoleScope,
    ) -> list[Directory]:
        """Get directories based on the scope.

        :param str base_dn: Base DN to start searching from.
        :param RoleScope scope: Scope of the role.
        """
        search_path = get_search_path(base_dn)
        if scope == RoleScope.BASE_OBJECT:
            path_filter = get_path_filter(path=search_path)
            directory = await self._session.scalar(
                select(Directory).where(path_filter),
            )
            return [directory] if directory else []

        elif scope == RoleScope.SINGLE_LEVEL:
            query = select(Directory).filter(
                and_(
                    func.cardinality(Directory.path) == len(search_path) + 1,
                    get_path_filter(
                        column=qa(Directory.path)[0 : len(search_path)],
                        path=search_path,
                    ),
                ),
            )
            return list((await self._session.scalars(query)).all())

        elif scope == RoleScope.WHOLE_SUBTREE:
            path_filter = get_path_filter(
                column=qa(Directory.path)[1 : len(search_path)],
                path=search_path,
            )
            return list(
                (
                    await self._session.scalars(
                        select(Directory).where(path_filter),
                    )
                ).all(),
            )

        else:
            raise ValueError(f"Invalid scope: {scope}")

    async def create(self, dto: AccessControlEntryDTO) -> None:
        """Create a new access control entry.

        :param dto: AccessControlEntryDTO object to create.
        """
        directories = await self._get_directories_with_scope(
            base_dn=dto.base_dn,
            scope=dto.scope,
        )

        if not directories:
            raise NoValidDistinguishedNameError(
                f"Invalid distinguished name: {dto.base_dn}",
            )

        new_ace = AccessControlEntry(
            role_id=dto.role_id,
            ace_type=AceType(dto.ace_type.value),
            depth=get_depth_by_dn(dto.base_dn),
            path=dto.base_dn,
            scope=RoleScope(dto.scope.value),
            entity_type_id=dto.entity_type_id,
            attribute_type_id=dto.attribute_type_id,
            is_allow=dto.is_allow,
            directories=directories,
        )

        self._session.add(new_ace)
        try:
            await self._session.flush()
        except IntegrityError:
            raise AccessControlEntryAddError(
                "Failed to add access control entries.",
            )

    async def create_bulk(self, dtos: list[AccessControlEntryDTO]) -> None:
        """Create multiple access control entries.

        :param list[AccessControlEntryDTO] dtos: List of AccessControlEntryDTO
            objects to create.
        """
        directory_cache = {}
        for ace in dtos:
            cache_key = (ace.base_dn, ace.scope)
            if cache_key not in directory_cache:
                directory_cache[
                    cache_key
                ] = await self._get_directories_with_scope(
                    base_dn=ace.base_dn,
                    scope=ace.scope,
                )

            if not directory_cache[cache_key]:
                raise NoValidDistinguishedNameError(
                    f"Invalid distinguished name: {ace.base_dn}",
                )

            new_ace = AccessControlEntry(
                role_id=ace.role_id,
                ace_type=AceType(ace.ace_type.value),
                depth=get_depth_by_dn(ace.base_dn),
                path=ace.base_dn,
                scope=RoleScope(ace.scope.value),
                entity_type_id=ace.entity_type_id,
                attribute_type_id=ace.attribute_type_id,
                is_allow=ace.is_allow,
                directories=directory_cache[cache_key],
            )
            self._session.add(new_ace)

        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            raise AccessControlEntryAddError(
                "Failed to add access control entries.",
            )

    async def update(self, _id: int, dto: AccessControlEntryDTO) -> None:
        """Update an existing access control entry.

        :param int _id: ID of the access control entry to update.
        :param AccessControlEntryDTO dto: AccessControlEntryDTO object
            with updated values.
        """
        ace = await self._get_raw(_id)

        ace.role_id = dto.role_id
        ace.ace_type = dto.ace_type
        ace.entity_type_id = dto.entity_type_id
        ace.attribute_type_id = dto.attribute_type_id
        ace.is_allow = dto.is_allow

        if dto.scope != ace.scope or dto.base_dn != ace.path:
            directories = await self._get_directories_with_scope(
                base_dn=dto.base_dn,
                scope=dto.scope,
            )
            if not directories:
                raise NoValidDistinguishedNameError(
                    f"Invalid distinguished name: {dto.base_dn}",
                )

            ace.directories.clear()
            ace.directories.extend(directories)
            ace.scope = dto.scope
            ace.path = dto.base_dn
            ace.depth = get_depth_by_dn(dto.base_dn)

        try:
            await self._session.flush()
        except IntegrityError:
            raise AccessControlEntryUpdateError(
                "Failed to update access control entry.",
            )

    async def delete(self, _id: int) -> None:
        """Delete an existing access control entry.

        :param int _id: ID of the access control entry to delete.
        """
        ace = await self._get_raw(_id)
        await self._session.execute(
            delete(AccessControlEntry).filter_by(id=ace.id),
        )
        await self._session.flush()

    async def migration_upgrade(self) -> None:  # TODO
        ace_rows_q = await self._session.execute(
            select(qa(AccessControlEntry.id), qa(AttributeTypeLegacy.name))
            .join(
                AttributeTypeLegacy,
                qa(AccessControlEntry.attribute_type_id)
                == qa(AttributeTypeLegacy.id),
            )
            .where(qa(AccessControlEntry.attribute_type_id).is_not(None)),
        )
        ace_rows = ace_rows_q.all()

        if ace_rows:
            attribute_names = {row.name for row in ace_rows}
            directory_rows_q = await self._session.execute(
                select(qa(Directory.name), qa(Directory.id))
                .join(
                    EntityType,
                    qa(EntityType.id) == qa(Directory.entity_type_id),
                )
                .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE)
                .where(qa(Directory.name).in_(attribute_names)),
            )
            directory_rows = directory_rows_q.all()
            directory_by_name = {row.name: row.id for row in directory_rows}

            updates = [
                {"ace_id": row.id, "directory_id": directory_by_name[row.name]}
                for row in ace_rows
                if row.name in directory_by_name
            ]
            if updates:
                for item in updates:
                    update_stmt = (
                        update(AccessControlEntry)
                        .where(qa(AccessControlEntry.id) == item["ace_id"])
                        .values(attribute_type_id=item["directory_id"])
                    )
                    await self._session.execute(update_stmt)

    async def migration_downgrade(self) -> None:  # TODO
        ace_rows_q = await self._session.execute(
            select(qa(AccessControlEntry.id), qa(Directory.name))
            .join(
                Directory,
                qa(AccessControlEntry.attribute_type_id) == qa(Directory.id),
            )
            .join(
                EntityType,
                qa(EntityType.id) == qa(Directory.entity_type_id),
            )
            .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE)
            .where(qa(AccessControlEntry.attribute_type_id).is_not(None)),
        )
        ace_rows = ace_rows_q.all()

        if ace_rows:
            attribute_names = {row.name for row in ace_rows}
            legacy_rows_q = await self._session.execute(
                select(qa(AttributeTypeLegacy.name), qa(AttributeTypeLegacy.id))  # noqa: E501
                .where(qa(AttributeTypeLegacy.name).in_(attribute_names)),
            )  # fmt: skip
            legacy_rows = legacy_rows_q.all()
            legacy_by_name = {row.name: row.id for row in legacy_rows}

            updates = [
                {"ace_id": row.id, "legacy_id": legacy_by_name[row.name]}
                for row in ace_rows
                if row.name in legacy_by_name
            ]
            if updates:
                for item in updates:
                    update_stmt = (
                        update(AccessControlEntry)
                        .where(qa(AccessControlEntry.id) == item["ace_id"])
                        .values(attribute_type_id=item["legacy_id"])
                    )
                    await self._session.execute(update_stmt)
