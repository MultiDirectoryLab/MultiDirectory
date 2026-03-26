"""LDF version use cases."""

from typing import ClassVar

from abstract_service import AbstractService
from enums import AuthorizationRules, LdfVersionStatus
from ldap_protocol.ldf.dto import LdfVersionDTO
from ldap_protocol.ldf.ldf_dao import LdfVersionDAO
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class LdfVersionUseCase(AbstractService):
    """LDF version use case."""

    __ldf_version_dao: LdfVersionDAO

    def __init__(self, ldf_version_dao: LdfVersionDAO) -> None:
        self.__ldf_version_dao = ldf_version_dao

    async def create(self, dto: LdfVersionDTO) -> None:
        """Create LDF version record."""
        await self.__ldf_version_dao.create(dto)

    async def update_status(
        self,
        version: str,
        status: LdfVersionStatus,
    ) -> None:
        """Update LDF version status."""
        await self.__ldf_version_dao.update_status(version, status)

    async def get(self, version: str) -> LdfVersionDTO:
        """Get LDF version by name."""
        return await self.__ldf_version_dao.get(version)

    async def get_latest_success(self) -> LdfVersionDTO:
        """Get last successful LDF version."""
        return await self.__ldf_version_dao.get_latest_by_status(
            LdfVersionStatus.SUCCESS,
        )

    async def get_latest_error(self) -> LdfVersionDTO:
        """Get last failed LDF version."""
        return await self.__ldf_version_dao.get_latest_by_status(
            LdfVersionStatus.ERROR,
        )

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Get paginated list of LDF versions."""
        return await self.__ldf_version_dao.get_paginator(params)

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {}
