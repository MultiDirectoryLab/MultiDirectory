"""RID Manager use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory
from ldap_protocol.rid_manager.exceptions import RIDManagerPoolExceededError
from ldap_protocol.rid_manager.rid_manager_gateway import RIDManagerGateway
from ldap_protocol.rid_manager.utils import from_qword, to_qword


class RIDManagerUseCase:
    """RID Manager use case."""

    RID_BLOCK_SIZE = 500
    # NOTE Domain Controller(with role Rid Master) attr
    # replace and change logic, when super DC is introduced

    def __init__(
        self,
        gateway: RIDManagerGateway,
        session: AsyncSession,
    ) -> None:
        """Initialize RID Manager use case."""
        self._gateway = gateway
        self._session = session

    async def allocate_pool(self) -> int:
        """Allocate pool."""
        available_pool = await self._gateway.get_rid_available_pool()
        lower, upper = from_qword(available_pool)

        if lower + self.RID_BLOCK_SIZE > upper:
            raise RIDManagerPoolExceededError("Available pool exceeded")

        new_available_pool = to_qword(lower + self.RID_BLOCK_SIZE, upper)
        await self._gateway.update_rid_available_pool(new_available_pool)

        return to_qword(lower, lower + self.RID_BLOCK_SIZE)

    async def choose_nearest_domain_controller(self) -> Directory:
        """Locate best Domain Controller via DNS SRV records."""
        # TODO: нужно через DNS определять ближайший DC # noqa
        # и использовать его для выдачи RID
        return await self._gateway.get_domain_controller()
