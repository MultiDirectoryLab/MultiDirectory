"""LDF version DAO."""

from sqlalchemy import delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from entities import LdfVersion
from enums import LdfVersionStatus
from ldap_protocol.ldif_directory_exchange.ldf_version.dto import LdfVersionDTO
from ldap_protocol.ldif_directory_exchange.ldf_version.exceptions import (
    LdfVersionAlreadyExistsError,
    LdfVersionNotFoundError,
)
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult
from repo.pg.tables import queryable_attr as qa


def _convert_model_to_dto(model: LdfVersion) -> LdfVersionDTO:
    return LdfVersionDTO(
        version=model.version,
        d_create=model.d_create,
        status=model.status,
    )


class LdfVersionDAO:
    """LDF version DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        self.__session = session

    async def get(self, version: str) -> LdfVersionDTO:
        model = await self.__session.get(LdfVersion, version)
        if not model:
            raise LdfVersionNotFoundError(
                f"LDF version '{version}' not found.",
            )
        return _convert_model_to_dto(model)

    async def get_all(self) -> list[LdfVersionDTO]:
        result = await self.__session.scalars(select(LdfVersion))
        return list(map(_convert_model_to_dto, result.all()))

    async def create(self, dto: LdfVersionDTO) -> None:
        exists_query = await self.__session.get(LdfVersion, dto.version)
        if exists_query:
            raise LdfVersionAlreadyExistsError(
                f"LDF version '{dto.version}' already exists.",
            )

        model = LdfVersion(
            version=dto.version,
            status=dto.status,
        )
        self.__session.add(model)
        await self.__session.flush()

    async def update(self, version: str, dto: LdfVersionDTO) -> None:
        model = await self.__session.get(LdfVersion, version)
        if not model:
            raise LdfVersionNotFoundError(
                f"LDF version '{version}' not found.",
            )
        model.status = dto.status
        await self.__session.flush()

    async def delete(self, version: str) -> None:
        await self.__session.execute(
            delete(LdfVersion).where(qa(LdfVersion.version) == version),
        )
        await self.__session.flush()

    async def update_status(
        self,
        version: str,
        status: LdfVersionStatus,
    ) -> None:
        model = await self.__session.get(LdfVersion, version)
        if not model:
            raise LdfVersionNotFoundError(
                f"LDF version '{version}' not found.",
            )
        model.status = status
        await self.__session.flush()

    async def get_latest_by_status(
        self,
        status: LdfVersionStatus,
    ) -> LdfVersionDTO:
        query = (
            select(LdfVersion)
            .where(qa(LdfVersion.status) == status)
            .order_by(desc(qa(LdfVersion.d_create)))
        )
        result = await self.__session.scalars(query)
        model = result.first()
        if not model:
            raise LdfVersionNotFoundError(
                f"No LDF version with status '{status.value}'.",
            )
        return _convert_model_to_dto(model)

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult[LdfVersion, LdfVersionDTO]:
        filters = []
        if params.query:
            filters.append(qa(LdfVersion.version).like(f"%{params.query}%"))

        query = (
            select(LdfVersion)
            .where(*filters)
            .order_by(desc(qa(LdfVersion.d_create)))
        )

        return await PaginationResult[LdfVersion, LdfVersionDTO].get(
            params=params,
            query=query,
            converter=_convert_model_to_dto,
            session=self.__session,
        )
