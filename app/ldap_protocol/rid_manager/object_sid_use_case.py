"""Object SID use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory
from enums import SidPrefix
from ldap_protocol.rid_manager.object_sid_gateway import ObjectSIDGateway
from ldap_protocol.rid_manager.rid_manager_use_case import RIDManagerUseCase
from ldap_protocol.rid_manager.rid_set_use_case import RIDSetUseCase
from ldap_protocol.utils.queries import get_base_directories


class ObjectSIDUseCase:
    """Object SID use case."""

    def __init__(
        self,
        gateway: ObjectSIDGateway,
        rid_set_use_case: RIDSetUseCase,
        session: AsyncSession,
        rid_manager_use_case: RIDManagerUseCase,
    ) -> None:
        """Initialize Object SID use case."""
        self._gateway = gateway
        self._rid_set_use_case = rid_set_use_case
        self._session = session
        self._rid_manager_use_case = rid_manager_use_case

    async def get(self, directory: Directory) -> str:
        """Get object SID."""
        return await self._gateway.get(directory)

    async def add(
        self,
        directory: Directory,
        rid: int | None = None,
        sid_prefix: SidPrefix = SidPrefix.DOMAIN_IDENTIFIER,
    ) -> None:
        """Add object SID."""
        if rid is None:
            domain_controller = await self._rid_manager_use_case.choose_nearest_domain_controller()  # noqa
            rid_set = await self._rid_set_use_case.get(domain_controller)
            rid = await self._rid_set_use_case.allocate_next_rid(
                rid_set,
            )

        if sid_prefix == SidPrefix.BUILT_IN_DOMAIN:
            object_sid = f"{sid_prefix}-{rid}"
        elif sid_prefix == SidPrefix.DOMAIN_IDENTIFIER:
            domain_identifier = await self.get_domain_identifier()
            object_sid = f"{sid_prefix}-{domain_identifier}-{rid}"

        await self._gateway.add(directory, object_sid)

    async def get_domain_identifier(self) -> str:
        """Get domain identifier."""
        domain = (await get_base_directories(self._session))[0]

        return await self._gateway.get_domain_identifier(domain)
